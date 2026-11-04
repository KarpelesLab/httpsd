//! Pieces shared across the blocking runtimes.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(feature = "rt-threadpool")]
use std::io::{ErrorKind, Read, Write};
#[cfg(feature = "rt-threadpool")]
use std::net::TcpStream;
#[cfg(feature = "rt-threadpool")]
use std::sync::Condvar;

#[cfg(feature = "rt-threadpool")]
use crate::error::Result;
#[cfg(feature = "rt-threadpool")]
use crate::session::Session;

/// Bounds concurrent connections per client IP so one source cannot consume the
/// whole global connection budget. A `max_per_ip` of 0 disables limiting.
pub(crate) struct PeerLimiter {
    counts: Mutex<HashMap<IpAddr, u32>>,
    max_per_ip: u32,
}

impl PeerLimiter {
    pub(crate) fn new(max_per_ip: u32) -> Arc<PeerLimiter> {
        Arc::new(PeerLimiter {
            counts: Mutex::new(HashMap::new()),
            max_per_ip,
        })
    }

    /// Admit a connection from `ip`. `ip == None` (peer address unavailable)
    /// always admits — it cannot be attributed, so the global caps govern it.
    /// Returns a guard that releases the slot on drop, or `None` when `ip` is at
    /// the per-IP cap (caller must drop the connection).
    pub(crate) fn admit(self: &Arc<Self>, ip: Option<IpAddr>) -> Option<PeerGuard> {
        let Some(ip) = ip.filter(|_| self.max_per_ip > 0) else {
            return Some(PeerGuard { limiter: None });
        };
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let slot = counts.entry(ip).or_insert(0);
        if *slot >= self.max_per_ip {
            return None;
        }
        *slot += 1;
        Some(PeerGuard {
            limiter: Some((Arc::clone(self), ip)),
        })
    }
}

/// Releases a per-IP connection slot when dropped. A `None` limiter is a no-op
/// guard (limiting disabled or peer unattributable).
pub(crate) struct PeerGuard {
    limiter: Option<(Arc<PeerLimiter>, IpAddr)>,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        if let Some((limiter, ip)) = &self.limiter {
            let mut counts = limiter.counts.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(slot) = counts.get_mut(ip) {
                *slot -= 1;
                if *slot == 0 {
                    counts.remove(ip); // don't leak entries for departed IPs
                }
            }
        }
    }
}

/// Read buffer size used by the blocking drive loop.
pub(crate) const READ_BUF: usize = 16 * 1024;

/// Per-operation inactivity timeout for blocking connections. A read or write
/// that makes no progress within this window fails, so a peer that connects and
/// then stalls (slowloris, dead keep-alive, a client that stops reading our
/// response) releases its worker thread instead of pinning it forever.
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Minimum number of bytes a peer must deliver within each [`IO_TIMEOUT`]
/// window for the connection to be considered as making real progress.
///
/// The per-read inactivity timeout ([`IO_TIMEOUT`]) only fires on a *fully idle*
/// read: a slow-trickle slowloris that dribbles a single byte every ~25s resets
/// that timer on every read and so pins a worker forever. To defeat that we also
/// require a minimum *throughput*: across any [`IO_TIMEOUT`] window the peer must
/// send at least this many bytes, otherwise the connection is dropped. The floor
/// is tiny — a TLS handshake, an HTTP request head, or any steady upload clears
/// it trivially in a single read — so legitimate slow-but-steady transfers keep
/// working while a byte-at-a-time trickle is shed (within at most ~2× the
/// window). The window resets every time the floor is met, so the rule applies
/// uniformly to the handshake, the request head, request bodies, and subsequent
/// keep-alive requests without ever penalizing bulk transfer.
pub(crate) const MIN_PROGRESS: usize = 256;

#[cfg(feature = "rt-threadpool")]
/// Apply [`IO_TIMEOUT`] to a freshly accepted stream. Errors are ignored: a
/// socket that won't take a timeout will still be bounded by the read/write
/// loop, and failing the connection here would be worse than serving it.
pub(crate) fn apply_timeouts(stream: &TcpStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
}

/// Backoff applied after a descriptor-exhaustion `accept()` error.
pub(crate) const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);

/// How long a graceful shutdown waits for in-flight connections to finish
/// before returning anyway. Each connection is already bounded by `IO_TIMEOUT`,
/// so this is a backstop. Used by the runtimes that actively drain (tokio, mio);
/// the thread pool drains by joining its workers instead.
#[cfg(any(feature = "rt-tokio", feature = "rt-mio"))]
pub(crate) const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);
/// Poll cadence for noticing a shutdown request on an otherwise-idle accept loop.
#[cfg(any(feature = "rt-threadpool", feature = "rt-tokio"))]
pub(crate) const SHUTDOWN_POLL: Duration = Duration::from_millis(25);

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

#[cfg(feature = "rt-threadpool")]
/// While a response body is streaming, how long the blocking loop waits for
/// the producer before checking the socket for input (h2 WINDOW_UPDATEs, a
/// closed connection). Stream data itself wakes the loop immediately.
pub(crate) const STREAM_INPUT_POLL: Duration = Duration::from_millis(50);

#[cfg(feature = "rt-threadpool")]
/// Read timeout used for the quick socket check while a body is streaming.
const STREAM_READ_PROBE: Duration = Duration::from_millis(1);

#[cfg(feature = "rt-threadpool")]
/// A one-shot wake flag a stream producer sets (via the session's waker) and
/// the blocking loop waits on.
#[derive(Default)]
pub(crate) struct Wake {
    flag: Mutex<bool>,
    cond: Condvar,
}

#[cfg(feature = "rt-threadpool")]
impl Wake {
    pub(crate) fn notify(&self) {
        *self.flag.lock().unwrap_or_else(|e| e.into_inner()) = true;
        self.cond.notify_one();
    }

    /// Wait until notified or `timeout` passes, then clear the flag.
    pub(crate) fn wait(&self, timeout: Duration) {
        let mut flag = self.flag.lock().unwrap_or_else(|e| e.into_inner());
        if !*flag {
            flag = self
                .cond
                .wait_timeout(flag, timeout)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        *flag = false;
    }
}

#[cfg(feature = "rt-threadpool")]
/// Drive one connection to completion over a blocking socket.
///
/// TLS is handled inside the [`Session`] (the handshake records flow through
/// the same read/flush cycle), so the same loop serves HTTP and HTTPS.
pub(crate) fn serve_blocking(stream: &mut TcpStream, session: &mut Session) -> Result<()> {
    serve_blocking_prefed(stream, session, &[])
}

#[cfg(feature = "rt-threadpool")]
/// Like [`serve_blocking`] but first feeds `initial` bytes already read from the
/// stream (e.g. the ClientHello consumed while choosing a certificate).
pub(crate) fn serve_blocking_prefed(
    stream: &mut TcpStream,
    session: &mut Session,
    initial: &[u8],
) -> Result<()> {
    serve_blocking_window(stream, session, initial, IO_TIMEOUT)
}

#[cfg(feature = "rt-threadpool")]
/// The blocking drive loop, with the inactivity/throughput `window` as a
/// parameter (always [`IO_TIMEOUT`] in production; shortened by tests).
fn serve_blocking_window(
    stream: &mut TcpStream,
    session: &mut Session,
    initial: &[u8],
    window: Duration,
) -> Result<()> {
    session.set_addrs(stream.peer_addr().ok(), stream.local_addr().ok());
    let wake = Arc::new(Wake::default());
    {
        let wake = Arc::clone(&wake);
        session.set_waker(move || wake.notify());
    }

    let mut buf = [0u8; READ_BUF];
    let mut pending = initial;
    // Whether the socket currently has the short streaming read timeout.
    let mut probing = false;
    // Minimum-throughput deadline that defeats slow-trickle slowloris (which the
    // per-read inactivity timeout alone cannot catch — see [`MIN_PROGRESS`]). The
    // peer must deliver at least `MIN_PROGRESS` bytes within each [`IO_TIMEOUT`]
    // window; the window resets whenever that floor is met. The wake-up cadence
    // is provided by the socket's own read timeout ([`apply_timeouts`]); the
    // deadline is enforced in software when a read returns, bounding a trickle
    // to at most ~2× the window. While a response body is streaming the peer is
    // legitimately quiet, so the window is held open.
    let mut window_deadline = Instant::now() + window;
    let mut window_bytes: usize = 0;
    // Feed bytes to the session without charging its processing time to the
    // peer: `received` runs the handler synchronously, and a handler that
    // takes longer than the window (a slow upstream, minutes of inference)
    // must not make a well-behaved client look like a slow-trickle attacker —
    // that would drop the finished response unsent. Only time spent waiting on
    // the socket counts against the throughput floor.
    let feed = |session: &mut Session, data: &[u8], deadline: &mut Instant| {
        let started = Instant::now();
        let r = session.received(data);
        *deadline += started.elapsed();
        r
    };
    loop {
        let received = if !pending.is_empty() {
            let r = feed(session, pending, &mut window_deadline);
            window_bytes = window_bytes.saturating_add(pending.len());
            pending = &[];
            r
        } else if session.is_streaming() {
            // Wait for the producer (woken at once by new data), then take a
            // quick look at the socket without blocking on it.
            wake.wait(STREAM_INPUT_POLL);
            if !probing {
                let _ = stream.set_read_timeout(Some(STREAM_READ_PROBE));
                probing = true;
            }
            window_deadline = Instant::now() + window;
            window_bytes = 0;
            match stream.read(&mut buf) {
                Ok(0) => break, // peer closed: drops the stream (producer sees it)
                Ok(n) => {
                    window_bytes = n;
                    feed(session, &buf[..n], &mut window_deadline)
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Ok(()),
                Err(e) if e.kind() == ErrorKind::Interrupted => Ok(()),
                Err(e) => return Err(e.into()),
            }
        } else {
            if probing {
                let _ = stream.set_read_timeout(Some(window));
                probing = false;
            }
            let n = stream.read(&mut buf)?;
            if n == 0 {
                break; // peer closed
            }
            window_bytes = window_bytes.saturating_add(n);
            feed(session, &buf[..n], &mut window_deadline)
        };

        // Enforce the minimum-throughput deadline. A peer that has not delivered
        // `MIN_PROGRESS` bytes by the end of a window is a slow-trickle attacker;
        // drop it. Meeting the floor opens a fresh window.
        if window_bytes >= MIN_PROGRESS {
            window_deadline = Instant::now() + window;
            window_bytes = 0;
        } else if Instant::now() >= window_deadline {
            break; // trickle: closed without making real progress
        }

        // Always flush queued output before acting on a parse error: a failed
        // feed may have produced a TLS alert (e.g. a refused renegotiation), and
        // the peer should receive it rather than a bare connection reset. Keep
        // pulling until the engine has nothing more — a file body is streamed in
        // bounded chunks across successive `to_send` calls, so we must fully
        // drain it here before going back to read (a slow GET client sends
        // nothing more, so a single flush would stall mid-body).
        loop {
            match session.to_send() {
                Ok(out) if !out.is_empty() => {
                    stream.write_all(&out)?;
                    stream.flush()?;
                    if !session.has_output() {
                        break;
                    }
                }
                _ => break,
            }
        }

        received?;
        if session.wants_close() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::PeerLimiter;
    use std::net::{IpAddr, Ipv4Addr};
    #[cfg(feature = "rt-threadpool")]
    use {
        super::serve_blocking_window,
        crate::proto::{Request, Response, StatusCode},
        crate::session::{Session, SessionConfig},
        std::io::{Read, Write},
        std::net::{TcpListener, TcpStream},
        std::sync::Arc,
        std::time::Duration,
    };

    #[cfg(feature = "rt-threadpool")]
    /// Serve one plain-HTTP connection on a loopback socket with a shortened
    /// throughput `window`, send `request` from the client side, and return
    /// everything the server wrote before closing.
    fn exchange(window: Duration, handler_delay: Duration, request: &[u8]) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Mirror `apply_timeouts`, with the shortened window.
            stream.set_read_timeout(Some(window)).unwrap();
            let handler = move |_req: &Request| {
                std::thread::sleep(handler_delay);
                Response::new(StatusCode::OK).body("done\n")
            };
            let mut session = Session::plain(SessionConfig::new(Arc::new(handler)));
            let _ = serve_blocking_window(&mut stream, &mut session, &[], window);
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        client.write_all(request).unwrap();
        let mut out = Vec::new();
        let _ = client.read_to_end(&mut out);
        server.join().unwrap();
        out
    }

    #[cfg(feature = "rt-threadpool")]
    /// Issue #7: a handler that runs longer than the throughput window on a
    /// small (< MIN_PROGRESS) request must still get its response delivered —
    /// time spent in the handler is not the peer trickling.
    #[test]
    fn slow_handler_response_is_not_dropped() {
        let out = exchange(
            Duration::from_millis(200),
            Duration::from_millis(600),
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        let text = String::from_utf8_lossy(&out);
        assert!(text.starts_with("HTTP/1.1 200"), "got: {text:?}");
        assert!(text.ends_with("done\n"), "got: {text:?}");
    }

    #[cfg(feature = "rt-threadpool")]
    /// The trickle rule still applies to the socket: a peer that sends a
    /// partial head and then goes quiet is dropped once the window passes.
    #[test]
    fn stalled_peer_is_still_dropped() {
        let out = exchange(
            Duration::from_millis(200),
            Duration::ZERO,
            b"GET / HTTP/1.1\r\nHost: x\r\n",
        );
        assert!(out.is_empty(), "got: {:?}", String::from_utf8_lossy(&out));
    }

    fn ip(n: u8) -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)))
    }

    #[test]
    fn caps_per_ip_and_releases_on_drop() {
        let limiter = PeerLimiter::new(2);

        // A cap of 2 admits two connections from the same IP...
        let g1 = limiter.admit(ip(1)).expect("first admits");
        let g2 = limiter.admit(ip(1)).expect("second admits");
        // ...then rejects the third.
        assert!(limiter.admit(ip(1)).is_none(), "third is over the cap");

        // A different IP is unaffected by the first IP's usage.
        let other = limiter.admit(ip(2)).expect("distinct IP admits");

        // Dropping a guard frees a slot for that IP.
        drop(g1);
        let g3 = limiter.admit(ip(1)).expect("freed slot re-admits");

        drop((g2, g3, other));

        // The map does not retain zero-count entries: once every guard for an IP
        // is dropped, admitting again must start from a fresh count.
        assert!(
            limiter.counts.lock().unwrap().is_empty(),
            "no zero-count entries retained after all guards drop"
        );
    }

    #[test]
    fn cap_zero_always_admits() {
        let limiter = PeerLimiter::new(0);
        // Unlimited: many connections from one IP all admit, and no entries are
        // tracked at all.
        let guards: Vec<_> = (0..100).map(|_| limiter.admit(ip(1)).unwrap()).collect();
        assert_eq!(guards.len(), 100);
        assert!(limiter.counts.lock().unwrap().is_empty());
    }

    #[test]
    fn none_ip_always_admits() {
        let limiter = PeerLimiter::new(1);
        // An unattributable peer (no address) always admits, even past the cap,
        // and is not recorded in the map.
        let _a = limiter.admit(None).expect("None admits");
        let _b = limiter.admit(None).expect("None admits again");
        assert!(limiter.counts.lock().unwrap().is_empty());
    }
}
