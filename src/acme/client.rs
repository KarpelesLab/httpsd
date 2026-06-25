//! A minimal ACME (RFC 8555) client over the `rsurl` HTTPS client.
//!
//! Covers exactly the flow this server needs: account registration (with ToS
//! agreement and optional contact email), order creation for a set of DNS
//! names, challenge fulfilment via a pluggable [`ChallengeSolver`]
//! (TLS-ALPN-01 / HTTP-01), CSR finalization, and certificate download.

use std::thread::sleep;
use std::time::{Duration, Instant};

use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::x509::{CertSigner, CertificationRequest, DistinguishedName};
use rsurl::Request;

use super::jose::{b64url, AccountKey, KeyId};
use super::json::{self, Value};
use crate::error::{Error, Result};

/// Let's Encrypt production directory URL.
pub const LETSENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt staging directory URL (untrusted certs, high rate limits).
pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Installs and removes challenge responses. The manager backs this with the
/// shared maps the TLS router (TLS-ALPN-01) and HTTP listener (HTTP-01) read.
pub trait ChallengeSolver {
    /// Challenge types this solver can satisfy, in preference order
    /// (e.g. `["tls-alpn-01", "http-01"]`).
    fn preferred(&self) -> &[&'static str];
    /// Make the challenge response retrievable by the CA.
    fn present(&self, typ: &str, host: &str, token: &str, key_auth: &str) -> Result<()>;
    /// Tear down a previously presented challenge.
    fn cleanup(&self, typ: &str, host: &str, token: &str);
}

/// A freshly issued certificate.
pub struct Issued {
    /// PEM certificate chain (leaf first).
    pub chain_pem: String,
    /// PEM private key for the certificate.
    pub key_pem: String,
}

/// The ACME directory endpoints we use.
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

/// An ACME client bound to one directory and account key.
pub struct AcmeClient {
    dir: Directory,
    account: AccountKey,
    kid: Option<String>,
    nonce: Option<String>,
    email: Option<String>,
}

impl AcmeClient {
    /// Connect to an ACME directory with the given account key. Pass the account
    /// `email` for the `contact` field (optional). The caller is responsible for
    /// having obtained ToS agreement from the operator before calling
    /// [`ensure_account`](Self::ensure_account).
    pub fn new(directory_url: &str, account: AccountKey, email: Option<String>) -> Result<AcmeClient> {
        let resp = http_get(directory_url)?;
        let doc = parse_json(&resp.body)?;
        let dir = Directory {
            new_nonce: field(&doc, "newNonce")?,
            new_account: field(&doc, "newAccount")?,
            new_order: field(&doc, "newOrder")?,
        };
        Ok(AcmeClient {
            dir,
            account,
            kid: None,
            nonce: None,
            email,
        })
    }

    /// The account key, e.g. to persist after a successful registration.
    pub fn account(&self) -> &AccountKey {
        &self.account
    }

    /// Register (or look up) the account, agreeing to the CA's terms of service.
    /// Idempotent: an existing account for this key resolves to the same URL.
    pub fn ensure_account(&mut self) -> Result<()> {
        let payload = match &self.email {
            Some(e) => json::obj(&[
                ("termsOfServiceAgreed", "true".into()),
                ("contact", format!(r#"["mailto:{}"]"#, json::escape(e))),
            ]),
            None => json::obj(&[("termsOfServiceAgreed", "true".into())]),
        };
        let url = self.dir.new_account.clone();
        let resp = self.post(&url, &payload, KeyId::Jwk)?;
        if resp.status >= 400 {
            return Err(acme_err("newAccount", &resp.body));
        }
        let kid = resp
            .header("location")
            .ok_or_else(|| Error::Acme("newAccount: no Location (account URL)".into()))?;
        self.kid = Some(kid.to_owned());
        Ok(())
    }

    /// Obtain a certificate for `dns_names`, driving challenges via `solver`.
    pub fn issue(&mut self, dns_names: &[&str], solver: &dyn ChallengeSolver) -> Result<Issued> {
        if self.kid.is_none() {
            self.ensure_account()?;
        }

        // 1. Create the order.
        let identifiers = dns_names
            .iter()
            .map(|d| format!(r#"{{"type":"dns","value":"{}"}}"#, json::escape(d)))
            .collect::<Vec<_>>()
            .join(",");
        let order_payload = format!(r#"{{"identifiers":[{identifiers}]}}"#);
        let new_order = self.dir.new_order.clone();
        let resp = self.post(&new_order, &order_payload, self.kid_auth()?)?;
        if resp.status >= 400 {
            return Err(acme_err("newOrder", &resp.body));
        }
        let order_url = resp
            .header("location")
            .ok_or_else(|| Error::Acme("newOrder: no order URL".into()))?
            .to_owned();
        let order = parse_json(&resp.body)?;

        // 2. Satisfy each authorization.
        let authzs = order
            .get("authorizations")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Acme("order has no authorizations".into()))?
            .to_vec();
        for authz in &authzs {
            let url = authz
                .as_str()
                .ok_or_else(|| Error::Acme("bad authorization URL".into()))?;
            self.do_authorization(url, solver)?;
        }

        // 3. Finalize with a CSR (and a fresh certificate key).
        let finalize = order
            .str_at("finalize")
            .ok_or_else(|| Error::Acme("order has no finalize URL".into()))?
            .to_owned();
        let mut rng = purecrypto::rng::OsRng;
        let cert_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let csr_der = build_csr(&cert_key, dns_names)?;
        let finalize_payload = format!(r#"{{"csr":"{}"}}"#, b64url(&csr_der));
        let resp = self.post(&finalize, &finalize_payload, self.kid_auth()?)?;
        if resp.status >= 400 {
            return Err(acme_err("finalize", &resp.body));
        }

        // 4. Poll the order to "valid", then download the certificate.
        let cert_url = self.poll_order(&order_url)?;
        let resp = self.post_as_get(&cert_url)?;
        if resp.status >= 400 {
            return Err(acme_err("certificate", &resp.body));
        }
        let chain_pem = String::from_utf8(resp.body)
            .map_err(|_| Error::Acme("certificate is not valid UTF-8 PEM".into()))?;

        Ok(Issued {
            chain_pem,
            key_pem: cert_key.to_sec1_pem(),
        })
    }

    fn do_authorization(&mut self, url: &str, solver: &dyn ChallengeSolver) -> Result<()> {
        let resp = self.post_as_get(url)?;
        if resp.status >= 400 {
            return Err(acme_err("authz", &resp.body));
        }
        let authz = parse_json(&resp.body)?;
        if authz.str_at("status") == Some("valid") {
            return Ok(()); // already authorized (reused)
        }
        let host = authz
            .get("identifier")
            .and_then(|i| i.str_at("value"))
            .ok_or_else(|| Error::Acme("authz missing identifier".into()))?
            .to_owned();
        let challenges = authz
            .get("challenges")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Acme("authz has no challenges".into()))?;

        // Pick the most-preferred challenge the solver supports.
        let (ctype, curl, token) = self
            .select_challenge(challenges, solver)
            .ok_or_else(|| Error::Acme("no supported challenge offered".into()))?;
        let key_auth = self.account.key_authorization(&token);

        solver.present(&ctype, &host, &token, &key_auth)?;
        let result = (|| {
            // Tell the CA we're ready (empty object payload).
            let resp = self.post(&curl, "{}", self.kid_auth()?)?;
            if resp.status >= 400 {
                return Err(acme_err("challenge", &resp.body));
            }
            self.poll_authorization(url)
        })();
        solver.cleanup(&ctype, &host, &token);
        result
    }

    fn select_challenge(
        &self,
        challenges: &[Value],
        solver: &dyn ChallengeSolver,
    ) -> Option<(String, String, String)> {
        for &want in solver.preferred() {
            for ch in challenges {
                if ch.str_at("type") == Some(want) {
                    let url = ch.str_at("url")?.to_owned();
                    let token = ch.str_at("token")?.to_owned();
                    return Some((want.to_owned(), url, token));
                }
            }
        }
        None
    }

    fn poll_authorization(&mut self, url: &str) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let resp = self.post_as_get(url)?;
            let authz = parse_json(&resp.body)?;
            match authz.str_at("status") {
                Some("valid") => return Ok(()),
                Some("pending") | Some("processing") => {}
                Some("invalid") => return Err(acme_err("authorization invalid", &resp.body)),
                other => {
                    return Err(Error::Acme(format!("unexpected authz status: {other:?}")));
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::Acme("authorization timed out".into()));
            }
            sleep(Duration::from_secs(2));
        }
    }

    /// Poll the order until `valid`, returning its `certificate` URL.
    fn poll_order(&mut self, order_url: &str) -> Result<String> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let resp = self.post_as_get(order_url)?;
            let order = parse_json(&resp.body)?;
            match order.str_at("status") {
                Some("valid") => {
                    return order
                        .str_at("certificate")
                        .map(str::to_owned)
                        .ok_or_else(|| Error::Acme("valid order has no certificate URL".into()));
                }
                Some("processing") | Some("pending") | Some("ready") => {}
                Some("invalid") => return Err(acme_err("order invalid", &resp.body)),
                other => return Err(Error::Acme(format!("unexpected order status: {other:?}"))),
            }
            if Instant::now() >= deadline {
                return Err(Error::Acme("order finalization timed out".into()));
            }
            sleep(Duration::from_secs(2));
        }
    }

    // ---- transport ----

    fn kid_auth(&self) -> Result<KeyId> {
        self.kid
            .clone()
            .map(KeyId::Kid)
            .ok_or_else(|| Error::Acme("no account registered".into()))
    }

    fn fresh_nonce(&mut self) -> Result<String> {
        let resp = http_head(&self.dir.new_nonce)?;
        resp.header("replay-nonce")
            .map(str::to_owned)
            .ok_or_else(|| Error::Acme("newNonce returned no Replay-Nonce".into()))
    }

    /// JWS-signed POST, refreshing the nonce and retrying once on `badNonce`.
    fn post(&mut self, url: &str, payload: &str, auth: KeyId) -> Result<rsurl::Response> {
        for attempt in 0..2 {
            let nonce = match self.nonce.take() {
                Some(n) => n,
                None => self.fresh_nonce()?,
            };
            let body = self.account.sign(url, &nonce, &auth, payload)?;
            let resp = http_post_jose(url, body)?;
            if let Some(n) = resp.header("replay-nonce") {
                self.nonce = Some(n.to_owned());
            }
            if resp.status == 400 && attempt == 0 && is_bad_nonce(&resp.body) {
                self.nonce = None; // force a fresh nonce and retry
                continue;
            }
            return Ok(resp);
        }
        unreachable!("post loop always returns")
    }

    fn post_as_get(&mut self, url: &str) -> Result<rsurl::Response> {
        let auth = self.kid_auth()?;
        self.post(url, "", auth)
    }
}

/// Build a DER CSR for `dns_names` signed by `key`.
fn build_csr(key: &BoxedEcdsaPrivateKey, dns_names: &[&str]) -> Result<Vec<u8>> {
    let subject = DistinguishedName::common_name(dns_names[0]);
    let csr = CertificationRequest::create(&CertSigner::Ecdsa(key), &subject, dns_names)
        .map_err(|e| Error::Acme(format!("CSR: {e:?}")))?;
    Ok(csr.to_der().to_vec())
}

fn field(doc: &Value, key: &str) -> Result<String> {
    doc.str_at(key)
        .map(str::to_owned)
        .ok_or_else(|| Error::Acme(format!("directory missing {key}")))
}

fn parse_json(body: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(body).map_err(|_| Error::Acme("non-UTF-8 response".into()))?;
    json::parse(text)
}

/// Whether a 400 body is an ACME `badNonce` error.
fn is_bad_nonce(body: &[u8]) -> bool {
    std::str::from_utf8(body)
        .ok()
        .and_then(|t| json::parse(t).ok())
        .and_then(|v| v.str_at("type").map(|s| s.contains("badNonce")))
        .unwrap_or(false)
}

/// Build an error from an ACME problem document (RFC 7807).
fn acme_err(ctx: &str, body: &[u8]) -> Error {
    let detail = std::str::from_utf8(body)
        .ok()
        .and_then(|t| json::parse(t).ok())
        .and_then(|v| v.str_at("detail").map(str::to_owned))
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
    Error::Acme(format!("{ctx}: {detail}"))
}

fn map_rsurl(e: rsurl::Error) -> Error {
    Error::Acme(format!("http: {e}"))
}

fn http_get(url: &str) -> Result<rsurl::Response> {
    Request::new("GET", url)
        .map_err(map_rsurl)?
        .send()
        .map_err(map_rsurl)
}

fn http_head(url: &str) -> Result<rsurl::Response> {
    Request::new("HEAD", url)
        .map_err(map_rsurl)?
        .send()
        .map_err(map_rsurl)
}

fn http_post_jose(url: &str, body: String) -> Result<rsurl::Response> {
    Request::new("POST", url)
        .map_err(map_rsurl)?
        .header("content-type", "application/jose+json")
        .body(body.into_bytes())
        .send()
        .map_err(map_rsurl)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_nonce_detection() {
        let body = br#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"bad"}"#;
        assert!(is_bad_nonce(body));
        assert!(!is_bad_nonce(br#"{"type":"urn:ietf:params:acme:error:malformed"}"#));
    }

    #[test]
    fn problem_detail_extracted() {
        let e = acme_err("newOrder", br#"{"type":"x","detail":"rejected: bad id"}"#);
        assert!(format!("{e}").contains("rejected: bad id"));
    }

    #[test]
    fn csr_builds_for_names() {
        let mut rng = purecrypto::rng::OsRng;
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let der = build_csr(&key, &["a.example", "b.example"]).unwrap();
        assert!(!der.is_empty());
    }
}
