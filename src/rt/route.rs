//! Per-connection TLS certificate routing for the ACME path: read the
//! ClientHello off the socket, then pick the certificate (cached/issued cert,
//! the `acme-tls/1` challenge cert, the loopback self-signed, or reject).

use std::io::Read;
use std::net::TcpStream;

use crate::acme::{AcmeManager, CertChoice};
use crate::error::Result;
use crate::net::clienthello::{self, ClientHelloInfo};

/// Cap on bytes buffered while waiting for a complete ClientHello.
const MAX_HELLO: usize = 16 * 1024;

/// Read from `stream` until a full ClientHello is buffered. Returns the consumed
/// bytes (to be replayed into the TLS engine) and the parsed info, or `None` if
/// the peer closed / sent too much non-TLS data.
pub(crate) fn read_client_hello(
    stream: &mut TcpStream,
) -> Result<Option<(Vec<u8>, ClientHelloInfo)>> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(info) = clienthello::peek(&buf)? {
            return Ok(Some((buf, info)));
        }
        if buf.len() > MAX_HELLO {
            return Ok(None);
        }
        let n = stream.read(&mut tmp)?;
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
