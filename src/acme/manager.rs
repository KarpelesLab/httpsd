//! [`AcmeManager`] ties the store, the protocol client, and the challenge
//! solvers together: it answers "what certificate do I serve for this SNI?",
//! issuing (and renewing) on demand with per-host single-flight, and exposes
//! the challenge state the TLS router and HTTP listener read.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use purecrypto::ec::BoxedEcdsaPrivateKey;
use purecrypto::hash::sha256;
use purecrypto::x509::Certificate;

use super::client::{AcmeClient, ChallengeSolver, LETSENCRYPT_PRODUCTION};
use super::jose::AccountKey;
use super::store::Store;
use crate::error::{Error, Result};
use crate::tls::TlsAcceptor;

/// Re-issue a certificate once it is within this window of expiry.
const RENEW_BEFORE_SECS: u64 = 30 * 86_400;

/// Configuration for automatic certificate management.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// ACME directory URL (defaults to Let's Encrypt production).
    pub directory_url: String,
    /// Whether the operator has accepted the CA's terms of service. Issuance is
    /// refused unless this is `true`.
    pub accept_tos: bool,
    /// Optional account contact email.
    pub email: Option<String>,
    /// If set, only these host names may be issued for; others are rejected.
    pub host_whitelist: Option<HashSet<String>>,
    /// Override the on-disk storage directory.
    pub cert_dir: Option<PathBuf>,
}

impl Default for AcmeConfig {
    fn default() -> AcmeConfig {
        AcmeConfig {
            directory_url: LETSENCRYPT_PRODUCTION.to_owned(),
            accept_tos: false,
            email: None,
            host_whitelist: None,
            cert_dir: None,
        }
    }
}

/// What the TLS router should do for a connection.
pub enum CertChoice {
    /// Complete the handshake with this acceptor.
    Serve(TlsAcceptor),
    /// Refuse the connection (e.g. host not in the whitelist).
    Reject,
}

struct Cached {
    acceptor: TlsAcceptor,
    not_after: Option<u64>,
}

/// Shared automatic-certificate manager. Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct AcmeManager {
    inner: Arc<Inner>,
}

struct Inner {
    cfg: AcmeConfig,
    store: Store,
    self_signed: TlsAcceptor,
    cache: Mutex<HashMap<String, Arc<Cached>>>,
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// host → TLS-ALPN-01 challenge acceptor (present during validation).
    alpn_challenges: Arc<Mutex<HashMap<String, TlsAcceptor>>>,
    /// HTTP-01 token → key authorization (served by the HTTP listener).
    http_challenges: Arc<Mutex<HashMap<String, String>>>,
}

impl AcmeManager {
    /// Create a manager, opening the on-disk store and a fallback self-signed
    /// identity (used for loopback and host-less connections).
    pub fn new(cfg: AcmeConfig) -> Result<AcmeManager> {
        let store = Store::open(cfg.cert_dir.clone())?;
        let self_signed = TlsAcceptor::self_signed(&["localhost"])?;
        Ok(AcmeManager {
            inner: Arc::new(Inner {
                cfg,
                store,
                self_signed,
                cache: Mutex::new(HashMap::new()),
                locks: Mutex::new(HashMap::new()),
                alpn_challenges: Arc::new(Mutex::new(HashMap::new())),
                http_challenges: Arc::new(Mutex::new(HashMap::new())),
            }),
        })
    }

    /// The fallback self-signed acceptor (loopback / no-SNI connections).
    pub fn self_signed(&self) -> TlsAcceptor {
        self.inner.self_signed.clone()
    }

    /// The TLS-ALPN-01 challenge acceptor for `host`, if a validation is in
    /// progress. The TLS router uses this when the ClientHello offers
    /// `acme-tls/1`.
    pub fn challenge_acceptor(&self, host: &str) -> Option<TlsAcceptor> {
        self.inner
            .alpn_challenges
            .lock()
            .unwrap()
            .get(&normalize(host))
            .cloned()
    }

    /// The HTTP-01 key authorization for `token`, if any (served by the HTTP
    /// listener at `/.well-known/acme-challenge/<token>`).
    pub fn http_challenge(&self, token: &str) -> Option<String> {
        self.inner
            .http_challenges
            .lock()
            .unwrap()
            .get(token)
            .cloned()
    }

    /// Decide which certificate to present for a connection.
    pub fn choose(&self, sni: Option<&str>, peer_is_loopback: bool) -> CertChoice {
        // Loopback never gets a public cert — there's nothing a CA could verify.
        if peer_is_loopback {
            return CertChoice::Serve(self.self_signed());
        }
        let Some(host) = sni.map(normalize).filter(|h| !h.is_empty()) else {
            // No SNI (bare IP over TLS): present the self-signed default.
            return CertChoice::Serve(self.self_signed());
        };
        if let Some(wl) = &self.inner.cfg.host_whitelist
            && !wl.contains(&host)
        {
            return CertChoice::Reject;
        }
        match self.get_or_issue(&host) {
            Ok(acceptor) => CertChoice::Serve(acceptor),
            Err(e) => {
                if cfg!(debug_assertions) {
                    eprintln!("httpsd: acme: no certificate for {host}: {e}");
                }
                CertChoice::Reject
            }
        }
    }

    /// Like [`choose`](Self::choose) but **never blocks on ACME issuance** —
    /// it serves only a cert already cached or on disk. Used by the QUIC/HTTP-3
    /// runtime, whose single event loop must not stall on a multi-second
    /// issuance; the TCP path issues, and HTTP/3 picks the cert up once it
    /// exists (browsers reach TCP first and upgrade via `Alt-Svc`).
    pub fn choose_cached(&self, sni: Option<&str>, peer_is_loopback: bool) -> CertChoice {
        if peer_is_loopback {
            return CertChoice::Serve(self.self_signed());
        }
        let Some(host) = sni.map(normalize).filter(|h| !h.is_empty()) else {
            return CertChoice::Serve(self.self_signed());
        };
        if let Some(wl) = &self.inner.cfg.host_whitelist
            && !wl.contains(&host)
        {
            return CertChoice::Reject;
        }
        if let Some(c) = self.inner.cache.lock().unwrap().get(&host).cloned() {
            return CertChoice::Serve(c.acceptor.clone());
        }
        match self.inner.store.load_cert(&host) {
            Ok(Some(stored)) => match TlsAcceptor::from_pem(&stored.chain_pem, &stored.key_pem) {
                Ok(acceptor) => {
                    let not_after = cert_not_after(&stored.chain_pem);
                    self.cache_put(&host, acceptor.clone(), not_after);
                    CertChoice::Serve(acceptor)
                }
                Err(_) => CertChoice::Reject,
            },
            // Not issued yet: don't block the QUIC loop — let the TCP path issue.
            _ => CertChoice::Reject,
        }
    }

    /// Return a ready acceptor for `host`, issuing or renewing as needed.
    fn get_or_issue(&self, host: &str) -> Result<TlsAcceptor> {
        let now = now_secs();

        // Fast path: a fresh cached cert.
        if let Some(c) = self.inner.cache.lock().unwrap().get(host).cloned()
            && !near_expiry(c.not_after, now)
        {
            return Ok(c.acceptor.clone());
        }

        // Serialize issuance per host.
        let lock = self.host_lock(host);
        let _guard = lock.lock().unwrap();

        // Re-check the cache now that we hold the lock.
        if let Some(c) = self.inner.cache.lock().unwrap().get(host).cloned()
            && !near_expiry(c.not_after, now)
        {
            return Ok(c.acceptor.clone());
        }

        // Try disk before talking to the CA.
        if let Some(stored) = self.inner.store.load_cert(host)? {
            let not_after = cert_not_after(&stored.chain_pem);
            if !near_expiry(not_after, now) {
                let acceptor = TlsAcceptor::from_pem(&stored.chain_pem, &stored.key_pem)?;
                self.cache_put(host, acceptor.clone(), not_after);
                return Ok(acceptor);
            }
            // Stored but near/at expiry: try to renew, fall back to it if the
            // renewal fails but it is still valid.
            match self.issue(host) {
                Ok(acceptor) => return Ok(acceptor),
                Err(e) if not_after.is_some_and(|t| t > now) => {
                    if cfg!(debug_assertions) {
                        eprintln!("httpsd: acme: renewal for {host} failed, serving existing: {e}");
                    }
                    let acceptor = TlsAcceptor::from_pem(&stored.chain_pem, &stored.key_pem)?;
                    self.cache_put(host, acceptor.clone(), not_after);
                    return Ok(acceptor);
                }
                Err(e) => return Err(e),
            }
        }

        // Nothing on disk: issue fresh.
        self.issue(host)
    }

    /// Issue a brand-new certificate for `host` via ACME and persist it.
    fn issue(&self, host: &str) -> Result<TlsAcceptor> {
        if !self.inner.cfg.accept_tos {
            return Err(Error::Acme(
                "automatic issuance disabled: the CA terms of service have not been accepted"
                    .into(),
            ));
        }
        let mut client = self.make_client()?;
        let solver = ManagerSolver {
            alpn: Arc::clone(&self.inner.alpn_challenges),
            http: Arc::clone(&self.inner.http_challenges),
        };
        let issued = client.issue(&[host], &solver)?;
        self.inner
            .store
            .save_cert(host, &issued.chain_pem, &issued.key_pem)?;
        let not_after = cert_not_after(&issued.chain_pem);
        let acceptor = TlsAcceptor::from_pem(&issued.chain_pem, &issued.key_pem)?;
        self.cache_put(host, acceptor.clone(), not_after);
        Ok(acceptor)
    }

    fn make_client(&self) -> Result<AcmeClient> {
        let account = match self.inner.store.load_account_key()? {
            Some(pem) => {
                let key = BoxedEcdsaPrivateKey::from_sec1_pem(&pem)
                    .map_err(|e| Error::Acme(format!("account key: {e:?}")))?;
                AccountKey::new(key)
            }
            None => {
                let acct = AccountKey::generate();
                self.inner
                    .store
                    .save_account_key(&acct.private_key().to_sec1_pem())?;
                acct
            }
        };
        AcmeClient::new(
            &self.inner.cfg.directory_url,
            account,
            self.inner.cfg.email.clone(),
        )
    }

    fn host_lock(&self, host: &str) -> Arc<Mutex<()>> {
        self.inner
            .locks
            .lock()
            .unwrap()
            .entry(host.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn cache_put(&self, host: &str, acceptor: TlsAcceptor, not_after: Option<u64>) {
        self.inner.cache.lock().unwrap().insert(
            host.to_owned(),
            Arc::new(Cached {
                acceptor,
                not_after,
            }),
        );
    }
}

/// The solver the manager hands to the ACME client: it stashes challenge
/// responses in the shared maps the runtime serves from.
struct ManagerSolver {
    alpn: Arc<Mutex<HashMap<String, TlsAcceptor>>>,
    http: Arc<Mutex<HashMap<String, String>>>,
}

impl ChallengeSolver for ManagerSolver {
    fn preferred(&self) -> &[&'static str] {
        &["tls-alpn-01", "http-01"]
    }

    fn present(&self, typ: &str, host: &str, token: &str, key_auth: &str) -> Result<()> {
        match typ {
            "tls-alpn-01" => {
                let digest = sha256(key_auth.as_bytes());
                let acceptor = TlsAcceptor::acme_challenge(host, &digest)?;
                self.alpn.lock().unwrap().insert(normalize(host), acceptor);
            }
            "http-01" => {
                self.http
                    .lock()
                    .unwrap()
                    .insert(token.to_owned(), key_auth.to_owned());
            }
            other => return Err(Error::Acme(format!("unsupported challenge: {other}"))),
        }
        Ok(())
    }

    fn cleanup(&self, typ: &str, host: &str, token: &str) {
        match typ {
            "tls-alpn-01" => {
                self.alpn.lock().unwrap().remove(&normalize(host));
            }
            "http-01" => {
                self.http.lock().unwrap().remove(token);
            }
            _ => {}
        }
    }
}

fn normalize(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a cert with this `not_after` should be renewed now.
fn near_expiry(not_after: Option<u64>, now: u64) -> bool {
    match not_after {
        Some(t) => now + RENEW_BEFORE_SECS >= t,
        None => false, // unknown expiry: don't churn
    }
}

/// Parse the leaf certificate's `notAfter` (Unix seconds) from a chain PEM.
fn cert_not_after(chain_pem: &str) -> Option<u64> {
    let cert = Certificate::from_pem(chain_pem).ok()?;
    Some(cert.validity().ok()?.not_after.to_unix())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_window() {
        let now = 1_000_000_000;
        assert!(near_expiry(Some(now + 10 * 86_400), now)); // 10 days left → renew
        assert!(!near_expiry(Some(now + 60 * 86_400), now)); // 60 days left → keep
        assert!(!near_expiry(None, now));
    }

    #[test]
    fn normalize_host() {
        assert_eq!(normalize(" Example.COM. "), "example.com");
    }
}
