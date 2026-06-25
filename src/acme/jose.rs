//! The JOSE bits ACME needs: base64url, the account JWK + its thumbprint, and
//! ES256 (ECDSA P-256 / SHA-256) JWS signing (RFC 7515/7518/7638, RFC 8555 §6.2).

use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::hash::{sha256, Sha256};

use super::json;
use crate::error::{Error, Result};

/// base64url **without** padding (RFC 4648 §5), the encoding JOSE uses.
pub fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[((n >> 18) & 0x3f) as usize] as char);
        out.push(A[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(A[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(A[(n & 0x3f) as usize] as char);
        }
    }
    out
}

/// An ACME account key: an ECDSA P-256 key plus its JOSE identity.
pub struct AccountKey {
    key: BoxedEcdsaPrivateKey,
}

impl AccountKey {
    /// Wrap an existing P-256 key.
    pub fn new(key: BoxedEcdsaPrivateKey) -> AccountKey {
        AccountKey { key }
    }

    /// Generate a fresh P-256 account key.
    pub fn generate() -> AccountKey {
        let mut rng = purecrypto::rng::OsRng;
        AccountKey {
            key: BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng),
        }
    }

    /// The underlying private key (e.g. to serialize for persistence).
    pub fn private_key(&self) -> &BoxedEcdsaPrivateKey {
        &self.key
    }

    /// The public JWK as canonical JSON (members in the RFC 7638 order so it
    /// doubles as the thumbprint input): `{"crv":"P-256","kty":"EC","x":..,"y":..}`.
    pub fn jwk_json(&self) -> String {
        let (x, y) = self.xy();
        format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            b64url(&x),
            b64url(&y)
        )
    }

    /// The RFC 7638 JWK thumbprint: SHA-256 of the canonical JWK JSON.
    pub fn thumbprint(&self) -> [u8; 32] {
        sha256(self.jwk_json().as_bytes())
    }

    /// The ACME key authorization for a challenge `token`:
    /// `token "." base64url(thumbprint)` (RFC 8555 §8.1).
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", b64url(&self.thumbprint()))
    }

    /// The affine X and Y coordinates (32 bytes each) from the SEC1 point.
    fn xy(&self) -> (Vec<u8>, Vec<u8>) {
        let sec1 = self.key.public_key().to_sec1(); // 0x04 || X(32) || Y(32)
        (sec1[1..33].to_vec(), sec1[33..65].to_vec())
    }

    /// Produce a flattened JWS (the JSON body ACME POSTs) over `payload` with
    /// the given protected-header members. `payload` is the raw JSON request
    /// body, or `""` for a POST-as-GET.
    ///
    /// `auth` selects the key identification: a JWK (new-account) or a `kid`
    /// account URL (everything else).
    pub fn sign(&self, url: &str, nonce: &str, auth: &KeyId, payload: &str) -> Result<String> {
        let auth_field = match auth {
            KeyId::Jwk => format!(r#""jwk":{}"#, self.jwk_json()),
            KeyId::Kid(kid) => format!(r#""kid":"{}""#, json::escape(kid)),
        };
        let protected = format!(
            r#"{{"alg":"ES256","nonce":"{}","url":"{}",{}}}"#,
            json::escape(nonce),
            json::escape(url),
            auth_field
        );

        let protected_b64 = b64url(protected.as_bytes());
        let payload_b64 = b64url(payload.as_bytes());
        let signing_input = format!("{protected_b64}.{payload_b64}");

        let sig = self
            .key
            .sign::<Sha256>(signing_input.as_bytes())
            .map_err(|e| Error::Tls(format!("acme jws sign: {e:?}")))?
            .to_bytes(CurveId::P256); // fixed r‖s, 64 bytes — JOSE ES256

        Ok(json::obj(&[
            ("protected", format!(r#""{protected_b64}""#)),
            ("payload", format!(r#""{payload_b64}""#)),
            ("signature", format!(r#""{}""#, b64url(&sig))),
        ]))
    }
}

/// How a JWS identifies its signing key.
pub enum KeyId {
    /// Embed the full public JWK (used only for `newAccount`/`keyChange`).
    Jwk,
    /// Reference the account URL via `kid` (used for all other requests).
    Kid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_vectors() {
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
        // url-safe alphabet: bytes that map to '-' and '_'
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn jwk_and_thumbprint_are_stable() {
        let k = AccountKey::generate();
        let j1 = k.jwk_json();
        assert!(j1.starts_with(r#"{"crv":"P-256","kty":"EC","x":"#));
        assert_eq!(k.thumbprint(), k.thumbprint());
        // key authorization shape: "<token>.<43-char b64url of 32 bytes>"
        let ka = k.key_authorization("tok");
        let parts: Vec<&str> = ka.split('.').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "tok");
        assert_eq!(parts[1].len(), 43);
    }

    #[test]
    fn jws_is_well_formed() {
        let k = AccountKey::generate();
        let body = k
            .sign("https://acme.test/x", "nonce123", &KeyId::Jwk, r#"{"a":1}"#)
            .unwrap();
        let v = json::parse(&body).unwrap();
        let prot_b64 = v.str_at("protected").unwrap();
        let sig = v.str_at("signature").unwrap();
        assert_eq!(sig.len(), 86); // 64-byte r‖s -> 86 b64url chars

        // The protected header decodes to the expected JSON with a JWK.
        let prot = String::from_utf8(b64url_decode(prot_b64)).unwrap();
        let ph = json::parse(&prot).unwrap();
        assert_eq!(ph.str_at("alg"), Some("ES256"));
        assert_eq!(ph.str_at("nonce"), Some("nonce123"));
        assert_eq!(ph.str_at("url"), Some("https://acme.test/x"));
        assert_eq!(ph.get("jwk").unwrap().str_at("crv"), Some("P-256"));

        // POST-as-GET uses an empty payload.
        let g = k.sign("https://acme.test/y", "n2", &KeyId::Kid("acc".into()), "").unwrap();
        assert_eq!(json::parse(&g).unwrap().str_at("payload"), Some(""));
    }

    // Minimal base64url decode for the test only.
    fn b64url_decode(s: &str) -> Vec<u8> {
        fn v(c: u8) -> u8 {
            match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'-' => 62,
                _ => 63, // '_'
            }
        }
        let mut out = Vec::new();
        let mut acc = 0u32;
        let mut bits = 0;
        for &c in s.as_bytes() {
            acc = (acc << 6) | v(c) as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    }
}
