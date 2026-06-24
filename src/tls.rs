//! TLS support, built on the sans-I/O [`purecrypto::tls`] engine.
//!
//! A [`TlsAcceptor`] holds a server [`Config`] (certificate chain + private
//! key). For each accepted socket it mints a [`TlsStream`], itself sans-I/O:
//! feed it ciphertext from the socket, pull decrypted application bytes,
//! push application bytes to encrypt, and drain ciphertext to write back.
//! [`crate::session::Session`] drives this together with the HTTP engine.

use std::sync::Arc;

use purecrypto::bignum::Uint;
use purecrypto::ec::BoxedEcdsaPrivateKey;
use purecrypto::ec::ed25519::Ed25519PrivateKey;
use purecrypto::rng::OsRng;
use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use purecrypto::tls::{Config, Connection, SigningKey};
use purecrypto::x509::{Certificate, DistinguishedName, Time, Validity};

use crate::error::{Error, Result};

fn tls_err<E: std::fmt::Debug>(e: E) -> Error {
    Error::Tls(format!("{e:?}"))
}

/// A reusable TLS server configuration. Cheap to clone (shares the underlying
/// config via `Arc`).
#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<Config>,
}

impl TlsAcceptor {
    /// Build an acceptor from a PEM certificate chain and a PEM private key.
    ///
    /// The certificate PEM may contain the leaf followed by intermediates. The
    /// key may be PKCS#8 (`PRIVATE KEY`), PKCS#1 RSA (`RSA PRIVATE KEY`), or
    /// SEC1 EC (`EC PRIVATE KEY`).
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<TlsAcceptor> {
        let chain = cert_chain_der(cert_pem)?;
        if chain.is_empty() {
            return Err(Error::Tls("no certificates found in PEM".into()));
        }
        let key = load_signing_key(key_pem)?;
        Ok(TlsAcceptor::from_identity(chain, key))
    }

    /// Build an acceptor by reading a certificate file and a key file.
    pub fn from_pem_files(
        cert_path: impl AsRef<std::path::Path>,
        key_path: impl AsRef<std::path::Path>,
    ) -> Result<TlsAcceptor> {
        let cert = std::fs::read_to_string(cert_path)?;
        let key = std::fs::read_to_string(key_path)?;
        TlsAcceptor::from_pem(&cert, &key)
    }

    /// Generate an ephemeral self-signed RSA certificate covering the given
    /// host names. Handy for local development; clients must opt out of
    /// verification or trust the generated certificate.
    pub fn self_signed(hostnames: &[&str]) -> Result<TlsAcceptor> {
        let primary = hostnames.first().copied().unwrap_or("localhost");
        let mut rng = OsRng;
        let key = RsaPrivateKey::<32>::generate(Uint::from_u64(65537), &mut rng, 20);
        let name = DistinguishedName::common_name(primary);
        let validity = Validity::new(
            Time::utc(2020, 1, 1, 0, 0, 0),
            Time::utc(2040, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_with_sans(&key, &name, &validity, 1, false, hostnames)
            .map_err(tls_err)?;
        let chain = vec![cert.to_der().to_vec()];
        let boxed = BoxedRsaPrivateKey::from_pkcs1_pem(&key.to_pkcs1_pem()).map_err(tls_err)?;
        Ok(TlsAcceptor::from_identity(chain, SigningKey::Rsa(boxed)))
    }

    fn from_identity(chain: Vec<Vec<u8>>, key: SigningKey) -> TlsAcceptor {
        let config = Config::builder()
            .rng(Arc::new(OsRng))
            .tls_only()
            .identity(chain, key)
            .alpn(vec![b"http/1.1".to_vec()])
            .build();
        TlsAcceptor {
            config: Arc::new(config),
        }
    }

    /// Begin a new server-side TLS connection. The handshake is driven by
    /// feeding the returned stream the bytes that arrive on the socket.
    pub fn accept(&self) -> Result<TlsStream> {
        let conn = Connection::server(&self.config).map_err(tls_err)?;
        Ok(TlsStream { conn })
    }
}

impl std::fmt::Debug for TlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptor").finish_non_exhaustive()
    }
}

/// One server-side TLS connection: a sans-I/O wrapper over
/// [`purecrypto::tls::Connection`].
pub struct TlsStream {
    conn: Connection,
}

impl TlsStream {
    /// Feed ciphertext received from the socket into the TLS engine.
    pub fn feed(&mut self, wire: &[u8]) -> Result<()> {
        let mut off = 0;
        while off < wire.len() {
            let n = self.conn.feed(&wire[off..]).map_err(tls_err)?;
            if n == 0 {
                break; // engine buffered the rest internally
            }
            off += n;
        }
        Ok(())
    }

    /// Drain all currently available decrypted application bytes.
    pub fn recv_all(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let chunk = self.conn.recv().map_err(tls_err)?;
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Queue application bytes to be encrypted and sent.
    pub fn send(&mut self, app: &[u8]) -> Result<()> {
        if !app.is_empty() {
            self.conn.send(app).map_err(tls_err)?;
        }
        Ok(())
    }

    /// Drain all ciphertext that must be written to the socket (handshake
    /// records and/or encrypted application data).
    pub fn pop_all(&mut self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let chunk = self.conn.pop().map_err(tls_err)?;
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Whether the TLS handshake has completed.
    pub fn is_handshake_complete(&self) -> bool {
        self.conn.is_handshake_complete()
    }

    /// Begin a clean shutdown (queues a `close_notify`).
    pub fn close(&mut self) -> Result<()> {
        self.conn.close().map_err(tls_err)
    }
}

// ---- PEM parsing ----

struct PemBlock {
    label: String,
    text: String,
    der: Vec<u8>,
}

/// Split a PEM document into its constituent blocks.
fn pem_blocks(pem: &str) -> Vec<PemBlock> {
    const BEGIN: &str = "-----BEGIN ";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(bpos) = rest.find(BEGIN) {
        let after = &rest[bpos + BEGIN.len()..];
        let Some(label_end) = after.find("-----") else {
            break;
        };
        let label = after[..label_end].to_owned();
        let end_marker = format!("-----END {label}-----");
        let body_start = bpos + BEGIN.len() + label_end + "-----".len();
        let Some(epos) = rest[body_start..].find(&end_marker) else {
            break;
        };
        let block_end = body_start + epos + end_marker.len();
        let text = rest[bpos..block_end].to_owned();
        if let Some(der) = base64_decode(&rest[body_start..body_start + epos]) {
            out.push(PemBlock { label, text, der });
        }
        rest = &rest[block_end..];
    }
    out
}

/// Decode standard-alphabet base64 (ignoring whitespace), tolerating optional
/// `=` padding. Returns `None` on invalid input.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Collect every `CERTIFICATE` block's DER, in order.
fn cert_chain_der(pem: &str) -> Result<Vec<Vec<u8>>> {
    let chain: Vec<Vec<u8>> = pem_blocks(pem)
        .into_iter()
        .filter(|b| b.label == "CERTIFICATE")
        .map(|b| b.der)
        .collect();
    Ok(chain)
}

/// Load the first private-key block as a TLS [`SigningKey`].
fn load_signing_key(pem: &str) -> Result<SigningKey> {
    for block in pem_blocks(pem) {
        match block.label.as_str() {
            "RSA PRIVATE KEY" => {
                let k = BoxedRsaPrivateKey::from_pkcs1_pem(&block.text).map_err(tls_err)?;
                return Ok(SigningKey::Rsa(k));
            }
            "EC PRIVATE KEY" => {
                let k = BoxedEcdsaPrivateKey::from_sec1_pem(&block.text).map_err(tls_err)?;
                return Ok(SigningKey::Ecdsa(k));
            }
            "PRIVATE KEY" => return signing_key_from_pkcs8(&block.text),
            _ => continue,
        }
    }
    Err(Error::Tls("no private key found in PEM".into()))
}

/// A PKCS#8 key may hold RSA, EC, or Ed25519 material; try each.
fn signing_key_from_pkcs8(text: &str) -> Result<SigningKey> {
    if let Ok(k) = BoxedRsaPrivateKey::from_pkcs8_pem(text) {
        return Ok(SigningKey::Rsa(k));
    }
    if let Ok(k) = BoxedEcdsaPrivateKey::from_pkcs8_pem(text) {
        return Ok(SigningKey::Ecdsa(k));
    }
    if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(text) {
        return Ok(SigningKey::Ed25519(k));
    }
    Err(Error::Tls(
        "PKCS#8 key is not RSA, EC, or Ed25519".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_round_trips() {
        let acceptor = TlsAcceptor::self_signed(&["localhost"]).expect("self-signed");
        let _stream = acceptor.accept().expect("accept");
    }

    #[test]
    fn pem_block_splitting() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let blocks = pem_blocks(pem);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[0].der, vec![0, 0, 0]);
    }
}
