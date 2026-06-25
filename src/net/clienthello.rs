//! Non-consuming TLS ClientHello inspection: extract the SNI host and offered
//! ALPN protocols from buffered handshake bytes, so the server can choose which
//! certificate to present (a cached one, an on-demand ACME issuance, or the
//! `acme-tls/1` challenge cert) *before* committing to a TLS connection.
//!
//! This delegates to [`purecrypto::tls::peek_client_hello`] and adds the small
//! [`ClientHelloInfo::wants_acme_tls`] helper.

use crate::error::{Error, Result};

/// What we learn from a ClientHello before the handshake proper.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// The SNI host name (RFC 6066), if the client sent one.
    pub server_name: Option<String>,
    /// The ALPN protocol IDs the client offered (RFC 7301), in order.
    pub alpn_protocols: Vec<Vec<u8>>,
}

impl ClientHelloInfo {
    /// Whether the client offered the `acme-tls/1` protocol (TLS-ALPN-01).
    pub fn wants_acme_tls(&self) -> bool {
        self.alpn_protocols.iter().any(|p| p == b"acme-tls/1")
    }
}

/// Inspect buffered bytes from the start of a TLS connection.
///
/// Returns `Ok(None)` if more bytes are needed, `Ok(Some(info))` once the
/// ClientHello is fully present, or `Err(..)` if the bytes are clearly not a
/// TLS ClientHello (e.g. someone spoke HTTP to the TLS port). Non-consuming.
pub fn peek(buf: &[u8]) -> Result<Option<ClientHelloInfo>> {
    match purecrypto::tls::peek_client_hello(buf) {
        Ok(Some(info)) => Ok(Some(ClientHelloInfo {
            server_name: info.server_name,
            alpn_protocols: info.alpn_protocols,
        })),
        Ok(None) => Ok(None),
        Err(e) => Err(Error::Tls(format!("client hello: {e:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS record-framed ClientHello with the given SNI + ALPN.
    fn client_hello(sni: Option<&str>, alpn: &[&[u8]]) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(host) = sni {
            let mut sn = Vec::new();
            sn.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes()); // list len
            sn.push(0); // host_name
            sn.extend_from_slice(&(host.len() as u16).to_be_bytes());
            sn.extend_from_slice(host.as_bytes());
            ext.extend_from_slice(&0x0000u16.to_be_bytes());
            ext.extend_from_slice(&(sn.len() as u16).to_be_bytes());
            ext.extend_from_slice(&sn);
        }
        if !alpn.is_empty() {
            let mut list = Vec::new();
            for p in alpn {
                list.push(p.len() as u8);
                list.extend_from_slice(p);
            }
            let mut a = Vec::new();
            a.extend_from_slice(&(list.len() as u16).to_be_bytes());
            a.extend_from_slice(&list);
            ext.extend_from_slice(&0x0010u16.to_be_bytes());
            ext.extend_from_slice(&(a.len() as u16).to_be_bytes());
            ext.extend_from_slice(&a);
        }

        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // one suite
        body.push(1); // compression len
        body.push(0); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(1); // ClientHello
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);

        let mut rec = Vec::new();
        rec.push(22); // handshake
        rec.extend_from_slice(&0x0301u16.to_be_bytes());
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni_and_alpn() {
        let rec = client_hello(Some("example.test"), &[b"h2", b"http/1.1"]);
        let info = peek(&rec).unwrap().unwrap();
        assert_eq!(info.server_name.as_deref(), Some("example.test"));
        assert_eq!(info.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert!(!info.wants_acme_tls());
    }

    #[test]
    fn detects_acme_tls() {
        let rec = client_hello(Some("a.test"), &[b"acme-tls/1"]);
        assert!(peek(&rec).unwrap().unwrap().wants_acme_tls());
    }

    #[test]
    fn no_sni_is_ok() {
        let rec = client_hello(None, &[]);
        let info = peek(&rec).unwrap().unwrap();
        assert!(info.server_name.is_none());
        assert!(info.alpn_protocols.is_empty());
    }

    #[test]
    fn partial_returns_none() {
        let rec = client_hello(Some("example.test"), &[b"h2"]);
        assert!(peek(&rec[..8]).unwrap().is_none());
        assert!(peek(&rec[..rec.len() - 5]).unwrap().is_none());
    }

    #[test]
    fn non_tls_never_yields_client_hello() {
        // Non-handshake bytes must never be mistaken for a ClientHello (the
        // engine returns Err or Ok(None), never Ok(Some)).
        assert!(!matches!(peek(b"GET / HTTP/1.1\r\n\r\n"), Ok(Some(_))));
    }
}
