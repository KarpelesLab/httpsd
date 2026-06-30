//! Pieces shared across the blocking runtimes.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::Result;
use crate::session::Session;

/// Read buffer size used by the blocking drive loop.
pub(crate) const READ_BUF: usize = 16 * 1024;

/// Per-operation inactivity timeout for blocking connections. A read or write
/// that makes no progress within this window fails, so a peer that connects and
/// then stalls (slowloris, dead keep-alive, a client that stops reading our
/// response) releases its worker thread instead of pinning it forever.
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Apply [`IO_TIMEOUT`] to a freshly accepted stream. Errors are ignored: a
/// socket that won't take a timeout will still be bounded by the read/write
/// loop, and failing the connection here would be worse than serving it.
pub(crate) fn apply_timeouts(stream: &TcpStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
}

/// Backoff applied after a descriptor-exhaustion `accept()` error.
pub(crate) const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// Minimum gap between logged accept errors; identical errors in between are
/// counted and reported as a suppressed total on the next emitted line.
const ACCEPT_LOG_EVERY: Duration = Duration::from_secs(5);

/// Handle a listener `accept()` error and report whether the caller should back
/// off before retrying.
///
/// On descriptor exhaustion (`EMFILE`/`ENFILE`) the listening socket stays
/// readable, so retrying immediately spins the CPU at 100% and writes one log
/// line per iteration — enough to fill a disk in hours (exactly how a 1024-fd
/// limit once turned into a 46 GB log). When this returns `true` the caller
/// should sleep for [`ACCEPT_BACKOFF`], giving in-flight connections time to
/// release descriptors. Logging is coalesced to at most one line per
/// [`ACCEPT_LOG_EVERY`] so a sustained failure can never flood the log.
pub(crate) fn note_accept_error(label: &str, e: &io::Error) -> bool {
    // EMFILE = 24, ENFILE = 23 on Linux and macOS.
    let exhausted = matches!(e.raw_os_error(), Some(24) | Some(23));

    static THROTTLE: Mutex<Option<(Instant, u64)>> = Mutex::new(None);
    if let Ok(mut guard) = THROTTLE.lock() {
        let now = Instant::now();
        let report = match *guard {
            Some((last, suppressed)) if now.duration_since(last) < ACCEPT_LOG_EVERY => {
                *guard = Some((last, suppressed + 1));
                None
            }
            other => {
                *guard = Some((now, 0));
                Some(other.map_or(0, |(_, suppressed)| suppressed))
            }
        };
        if let Some(suppressed) = report {
            if suppressed > 0 {
                eprintln!("httpsd: {label}: {e} (+{suppressed} suppressed)");
            } else {
                eprintln!("httpsd: {label}: {e}");
            }
        }
    }

    exhausted
}

/// Drive one connection to completion over a blocking byte stream.
///
/// This is transport-agnostic: `stream` may be a plain `TcpStream` or any
/// `Read + Write`. TLS is handled inside the [`Session`] (the handshake records
/// flow through the same read/flush cycle), so the same loop serves HTTP and
/// HTTPS.
pub(crate) fn serve_blocking<S: Read + Write>(stream: &mut S, session: &mut Session) -> Result<()> {
    serve_blocking_prefed(stream, session, &[])
}

/// Like [`serve_blocking`] but first feeds `initial` bytes already read from the
/// stream (e.g. the ClientHello consumed while choosing a certificate).
pub(crate) fn serve_blocking_prefed<S: Read + Write>(
    stream: &mut S,
    session: &mut Session,
    initial: &[u8],
) -> Result<()> {
    let mut buf = [0u8; READ_BUF];
    let mut pending = initial;
    loop {
        let received = if !pending.is_empty() {
            let r = session.received(pending);
            pending = &[];
            r
        } else {
            let n = stream.read(&mut buf)?;
            if n == 0 {
                break; // peer closed
            }
            session.received(&buf[..n])
        };

        // Always flush queued output before acting on a parse error: a failed
        // feed may have produced a TLS alert (e.g. a refused renegotiation), and
        // the peer should receive it rather than a bare connection reset.
        if let Ok(out) = session.to_send()
            && !out.is_empty()
        {
            stream.write_all(&out)?;
            stream.flush()?;
        }

        received?;
        if session.wants_close() {
            break;
        }
    }
    Ok(())
}
