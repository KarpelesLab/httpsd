//! Per-connection TLS certificate routing for the ACME path: read the
//! ClientHello off the socket, then pick the certificate (cached/issued cert,
//! the `acme-tls/1` challenge cert, the loopback self-signed, or reject).

use std::io::{ErrorKind, Read};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::acme::{AcmeManager, CertChoice};
use crate::error::Result;
use crate::net::clienthello::{self, ClientHelloInfo};

/// Cap on bytes buffered while waiting for a complete ClientHello.
const MAX_HELLO: usize = 16 * 1024;

/// Absolute wall-clock deadline for buffering a complete ClientHello.
///
/// The per-read inactivity timeout cannot stop a slow-trickle slowloris that
/// dribbles a byte at a time (each read resets the timer), so the TLS-routing
/// handshake phase gets a hard ceiling: a real client's ClientHello arrives in
/// the first packet, well under a second, so a few seconds is comfortably
/// generous while still bounding an attacker. Once it elapses we give up on the
/// connection (`Ok(None)`), releasing the worker.
const HELLO_DEADLINE: Duration = Duration::from_secs(10);

/// Read from `stream` until a full ClientHello is buffered. Returns the consumed
/// bytes (to be replayed into the TLS engine) and the parsed info, or `None` if
/// the peer closed / sent too much non-TLS data / missed the [`HELLO_DEADLINE`].
///
/// While reading, the socket's read timeout is clamped to the time left before
/// the deadline so a blocking read can never overshoot it. The caller is
/// responsible for restoring the normal I/O timeout afterwards (see
/// `apply_timeouts`).
pub(crate) fn read_client_hello(
    stream: &mut TcpStream,
) -> Result<Option<(Vec<u8>, ClientHelloInfo)>> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    let deadline = Instant::now() + HELLO_DEADLINE;
    loop {
        if let Some(info) = clienthello::peek(&buf)? {
            return Ok(Some((buf, info)));
        }
        if buf.len() > MAX_HELLO {
            return Ok(None);
        }
        // Bound the next read by the time remaining before the deadline.
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => d,
            _ => return Ok(None), // handshake-phase deadline exceeded
        };
        stream.set_read_timeout(Some(remaining)).ok();
        let n = match stream.read(&mut tmp) {
            Ok(n) => n,
            // A timed-out read means the peer went idle or hit the deadline.
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Choose the certificate for a peeked ClientHello.
pub(crate) fn choose(mgr: &AcmeManager, info: &ClientHelloInfo, loopback: bool) -> CertChoice {
    // A TLS-ALPN-01 validation connection must get the challenge cert (and only
    // when one is actually pending for that host).
    if info.wants_acme_tls() {
        return match info
            .server_name
            .as_deref()
            .and_then(|h| mgr.challenge_acceptor(h))
        {
            Some(acceptor) => CertChoice::Serve(acceptor),
            None => CertChoice::Reject,
        };
    }
    mgr.choose(info.server_name.as_deref(), loopback)
}
