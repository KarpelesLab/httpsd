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
    let mut buf = [0u8; READ_BUF];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break; // peer closed
        }
        session.received(&buf[..n])?;
        let out = session.to_send()?;
        if !out.is_empty() {
            stream.write_all(&out)?;
            stream.flush()?;
        }
        if session.wants_close() {
            break;
        }
    }
    Ok(())
}
