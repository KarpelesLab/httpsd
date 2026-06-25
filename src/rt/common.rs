//! Pieces shared across the blocking runtimes.

use std::io::{Read, Write};

use crate::error::Result;
use crate::session::Session;

/// Read buffer size used by the blocking drive loop.
pub(crate) const READ_BUF: usize = 16 * 1024;

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
            && !out.is_empty() {
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
