//! TLS support, built on the sans-I/O [`purecrypto::tls`] engine.
//!
//! A [`TlsAcceptor`] holds a server [`Config`] (certificate chain + private
//! key). For each accepted socket it mints a [`TlsStream`], itself sans-I/O:
//! feed it ciphertext from the socket, pull decrypted application bytes,
//! push application bytes to encrypt, and drain ciphertext to write back.
//! [`crate::session::Session`] drives this together with the HTTP engine.

use std::sync::Arc;

use purecrypto::ec::ed25519::Ed25519PrivateKey;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::rng::OsRng;
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::tls::{Config, Connection, SigningKey};
use purecrypto::x509::{AnyPrivateKey, Certificate, DistinguishedName, Time, Validity};
#[cfg(feature = "acme")]
use purecrypto::x509::{extension::subject_alt_name, CertSigner, Extension, GeneralName};

use crate::error::{Error, Result};

fn tls_err<E: std::fmt::Debug>(e: E) -> Error {
    Error::Tls(format!("{e:?}"))
}

/// A reusable TLS server configuration. Cheap to clone (shares the underlying
/// config via `Arc`).
#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<Config>,
    /// The certificate chain (DER, leaf first) and the key as PEM, retained so
    /// the same identity can also mint per-connection QUIC configs for HTTP/3
    /// (`QuicConfig`/`SigningKey` are neither `Clone` nor reusable across
    /// connections, so the key PEM is re-parsed on demand).
    #[cfg(feature = "h3")]
    chain: Vec<Vec<u8>>,
    #[cfg(feature = "h3")]
    key_pem: Arc<String>,
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
        TlsAcceptor::build(chain, key_pem.to_owned())
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

    /// Generate an ephemeral self-signed certificate covering the given host
    /// names. Uses an ECDSA P-256 key, which generates near-instantly (unlike
    /// RSA). Handy for local development; clients must opt out of verification
    /// or trust the generated certificate.
    pub fn self_signed(hostnames: &[&str]) -> Result<TlsAcceptor> {
        let primary = hostnames.first().copied().unwrap_or("localhost");
        let mut rng = OsRng;
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name(primary);
        let validity = Validity::new(
            Time::utc(2020, 1, 1, 0, 0, 0),
            Time::utc(2040, 1, 1, 0, 0, 0),
        );
        // Keep the SEC1 PEM so `build`/`quic_config` can re-parse the identity.
        let key_pem = key.to_sec1_pem();
        let any = AnyPrivateKey::Ecdsa(key);
        let cert = Certificate::self_signed_with_sans(&any, &name, &validity, 1, false, hostnames)
            .map_err(tls_err)?;
        let chain = vec![cert.to_der().to_vec()];
        TlsAcceptor::build(chain, key_pem)
    }

    fn build(chain: Vec<Vec<u8>>, key_pem: String) -> Result<TlsAcceptor> {
        // Offer HTTP/2 ahead of HTTP/1.1 when compiled in; the client picks.
        let alpn = if cfg!(feature = "h2") {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        TlsAcceptor::build_with_alpn(chain, key_pem, alpn)
    }

    fn build_with_alpn(
        chain: Vec<Vec<u8>>,
        key_pem: String,
        alpn: Vec<Vec<u8>>,
    ) -> Result<TlsAcceptor> {
        let key = load_signing_key(&key_pem)?;
        let config = Config::builder()
            .rng(Arc::new(OsRng))
            .tls_only()
            .identity(chain.clone(), key)
            .alpn(alpn)
            .build();
        Ok(TlsAcceptor {
            config: Arc::new(config),
            #[cfg(feature = "h3")]
            chain,
            #[cfg(feature = "h3")]
            key_pem: Arc::new(key_pem),
        })
    }

    /// Build the special acceptor for an ACME **TLS-ALPN-01** challenge
    /// (RFC 8737): a self-signed cert for `host` carrying the critical
    /// `id-pe-acmeIdentifier` extension with `key_auth_digest`
    /// (`SHA-256(key authorization)`), and an ALPN of exactly `acme-tls/1`.
    /// The CA opens an `acme-tls/1` connection and validates this cert; no
    /// application data flows.
    #[cfg(feature = "acme")]
    pub fn acme_challenge(host: &str, key_auth_digest: &[u8; 32]) -> Result<TlsAcceptor> {
        let mut rng = OsRng;
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let name = DistinguishedName::common_name(host);
        let validity = Validity::new(
            Time::utc(2020, 1, 1, 0, 0, 0),
            Time::utc(2040, 1, 1, 0, 0, 0),
        );
        let san = subject_alt_name(&[GeneralName::Dns(host.to_owned())]);
        // extnValue is OCTET STRING; its content is itself an OCTET STRING of
        // the 32-byte digest. `Extension.value` is wrapped in the outer OCTET
        // STRING at serialization, so it must hold the inner DER `04 20 <32>`.
        let mut acme_value = vec![0x04, 0x20];
        acme_value.extend_from_slice(key_auth_digest);
        let acme_ext = Extension {
            oid: vec![1, 3, 6, 1, 5, 5, 7, 1, 31], // id-pe-acmeIdentifier
            critical: true,
            value: acme_value,
        };
        let cert =
            Certificate::self_signed_with_extensions(&CertSigner::Ecdsa(&key), &name, &validity, 1, &[san, acme_ext])
                .map_err(tls_err)?;
        let chain = vec![cert.to_der().to_vec()];
        TlsAcceptor::build_with_alpn(chain, key.to_sec1_pem(), vec![b"acme-tls/1".to_vec()])
    }

    /// Begin a new server-side TLS connection. The handshake is driven by
    /// feeding the returned stream the bytes that arrive on the socket.
    pub fn accept(&self) -> Result<TlsStream> {
        let conn = Connection::server(&self.config).map_err(tls_err)?;
        Ok(TlsStream { conn })
    }

    /// Build a fresh server [`QuicConfig`](purecrypto::quic::QuicConfig) for one
    /// HTTP/3 connection, advertising the `h3` ALPN. A new config (and freshly
    /// parsed signing key) is needed per connection because neither type is
    /// reusable.
    // `QuicConfig` is `#[non_exhaustive]`, so it can only be built by mutating
    // a `default()` — hence the field reassignment.
    #[cfg(feature = "h3")]
    #[allow(clippy::field_reassign_with_default)]
    pub fn quic_config(&self) -> Result<purecrypto::quic::QuicConfig> {
        use purecrypto::quic::{QuicConfig, TransportParameters};

        let key = load_signing_key(&self.key_pem)?;
        let tls = Config::builder()
            .rng(Arc::new(OsRng))
            .tls_only()
            .identity(self.chain.clone(), key)
            .alpn(vec![b"h3".to_vec()])
            .build();

        let transport_params = TransportParameters {
            max_idle_timeout_ms: Some(30_000),
            max_udp_payload_size: Some(1500),
            initial_max_data: Some(8 << 20),
            initial_max_stream_data_bidi_local: Some(1 << 20),
            initial_max_stream_data_bidi_remote: Some(1 << 20),
            initial_max_stream_data_uni: Some(1 << 20),
            initial_max_streams_bidi: Some(128),
            initial_max_streams_uni: Some(8),
            active_connection_id_limit: Some(2),
            ..TransportParameters::default()
        };

        let mut cfg = QuicConfig::default();
        cfg.tls = tls;
        cfg.transport_params = transport_params;
        Ok(cfg)
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

    /// The ALPN protocol negotiated during the handshake (e.g. `b"h2"` or
    /// `b"http/1.1"`), once available.
    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        self.conn.alpn_selected().map(|p| p.to_vec())
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
