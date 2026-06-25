//! Non-consuming TLS ClientHello inspection: extract the SNI host and offered
//! ALPN protocols from buffered handshake bytes, so the server can choose which
//! certificate to present (a cached one, an on-demand ACME issuance, or the
//! `acme-tls/1` challenge cert) *before* committing to a TLS connection.
//!
//! This is a stopgap for an upstream `purecrypto::tls::peek_client_hello`; the
//! rest of the crate goes through [`peek`] so swapping to the library version
//! is a one-line change.

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

/// A bounds-checked forward reader over a byte slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    /// Take `n` bytes, or `None` if not enough remain (incomplete input).
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u16(&mut self) -> Option<usize> {
        self.take(2).map(|s| ((s[0] as usize) << 8) | s[1] as usize)
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|s| ((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
    }
}

/// Inspect buffered bytes from the start of a TLS connection.
///
/// Returns `Ok(None)` if more bytes are needed, `Ok(Some(info))` once the
/// ClientHello is fully present, or `Err(..)` if the bytes are clearly not a
/// TLS ClientHello (e.g. someone spoke HTTP to the TLS port).
pub fn peek(buf: &[u8]) -> Result<Option<ClientHelloInfo>> {
    // Reassemble the handshake message from one or more TLS plaintext records.
    let mut handshake = Vec::new();
    let mut r = Reader::new(buf);
    loop {
        if r.remaining() < 5 {
            return Ok(None); // need a full record header
        }
        let ctype = r.u8().unwrap();
        if ctype != 22 {
            return Err(Error::Tls("not a TLS handshake record".into()));
        }
        let _ver = r.u16().unwrap();
        let len = r.u16().unwrap();
        match r.take(len) {
            Some(frag) => handshake.extend_from_slice(frag),
            None => return Ok(None), // record body not fully arrived
        }
        // A ClientHello fits in the first record in practice; once we have
        // enough handshake bytes to parse, stop pulling records.
        match parse_handshake(&handshake)? {
            Some(info) => return Ok(Some(info)),
            None => continue, // need another record fragment
        }
    }
}

/// Parse a (possibly partial) reassembled handshake message. `Ok(None)` means
/// more bytes are needed.
fn parse_handshake(hs: &[u8]) -> Result<Option<ClientHelloInfo>> {
    let mut r = Reader::new(hs);
    let Some(msg_type) = r.u8() else {
        return Ok(None);
    };
    if msg_type != 1 {
        return Err(Error::Tls("not a ClientHello".into()));
    }
    let Some(body_len) = r.u24() else {
        return Ok(None);
    };
    let Some(body) = r.take(body_len) else {
        return Ok(None); // full ClientHello body not yet reassembled
    };

    let mut b = Reader::new(body);
    // legacy_version(2) + random(32)
    if b.take(2).is_none() || b.take(32).is_none() {
        return Err(Error::Tls("short ClientHello".into()));
    }
    // legacy_session_id
    let sid = b.u8().ok_or_else(short)?;
    b.take(sid as usize).ok_or_else(short)?;
    // cipher_suites
    let cs = b.u16().ok_or_else(short)?;
    b.take(cs).ok_or_else(short)?;
    // legacy_compression_methods
    let comp = b.u8().ok_or_else(short)?;
    b.take(comp as usize).ok_or_else(short)?;

    // Extensions are optional (TLS 1.2 may omit them entirely).
    let mut info = ClientHelloInfo::default();
    let Some(ext_total) = b.u16() else {
        return Ok(Some(info));
    };
    let ext_bytes = b.take(ext_total).ok_or_else(short)?;

    let mut e = Reader::new(ext_bytes);
    while e.remaining() > 0 {
        let etype = e.u16().ok_or_else(short)?;
        let elen = e.u16().ok_or_else(short)?;
        let edata = e.take(elen).ok_or_else(short)?;
        match etype {
            0x0000 => info.server_name = parse_sni(edata),
            0x0010 => info.alpn_protocols = parse_alpn(edata),
            _ => {}
        }
    }
    Ok(Some(info))
}

fn short() -> Error {
    Error::Tls("malformed ClientHello extension".into())
}

/// server_name extension: ServerNameList { list_len(2), [ name_type(1), len(2), name ] }.
fn parse_sni(data: &[u8]) -> Option<String> {
    let mut r = Reader::new(data);
    let _list_len = r.u16()?;
    while r.remaining() >= 3 {
        let name_type = r.u8()?;
        let len = r.u16()?;
        let name = r.take(len)?;
        if name_type == 0 {
            // host_name; must be valid UTF-8 (ASCII in practice).
            return std::str::from_utf8(name).ok().map(|s| s.to_owned());
        }
    }
    None
}

/// ALPN extension: ProtocolNameList { list_len(2), [ len(1), name ]* }.
fn parse_alpn(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut r = Reader::new(data);
    if r.u16().is_none() {
        return out;
    }
    while r.remaining() > 0 {
        let Some(len) = r.u8() else { break };
        match r.take(len as usize) {
            Some(p) => out.push(p.to_vec()),
            None => break,
        }
    }
    out
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
    fn non_tls_errors() {
        assert!(peek(b"GET / HTTP/1.1\r\n\r\n").is_err());
    }
}
