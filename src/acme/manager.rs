//! [`AcmeManager`] ties the store, the protocol client, and the challenge
//! solvers together: it answers "what certificate do I serve for this SNI?",
//! issuing (and renewing) on demand with per-host single-flight, and exposes
//! the challenge state the TLS router and HTTP listener read.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// Maximum number of successfully-issued certs kept in memory. The on-disk store
/// is the source of truth; evicted entries are reloaded cheaply on next use.
/// Bounding this stops the success cache growing without limit under many
/// distinct SNIs.
const CACHE_MAX: usize = 1024;

/// After an issuance failure for a host, refuse to re-attempt for this long.
/// This negative cache stops a non-issuable SNI from re-running the full
/// blocking order/poll flow (which can sleep tens of seconds) on every
/// connection.
const NEG_CACHE_COOLDOWN_SECS: u64 = 300;

/// Maximum number of remembered issuance failures. Bounds the negative cache so
/// an attacker hitting unbounded distinct SNIs cannot grow memory without limit.
const NEG_CACHE_MAX: usize = 4096;

/// Maximum number of certificate issuances allowed to run concurrently. Each
/// issuance can block for tens of seconds; this caps the worst-case number of
/// threads parked in the ACME flow regardless of how many distinct SNIs arrive.
const MAX_INFLIGHT: usize = 16;

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
    /// Host to route by when a connection sends no SNI (e.g. a bare-IP TLS
    /// client, or a tool that omits SNI). When set, such connections are served
    /// this host's certificate instead of the self-signed fallback. It is still
    /// subject to `host_whitelist`, so include it there if a whitelist is set.
    pub default_host: Option<String>,
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
            default_host: None,
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

/// A size-bounded, approximately-LRU cache of issued acceptors. Reads bump a
/// monotonic tick; when full, the least-recently-used entry is evicted.
struct CertCache {
    map: HashMap<String, (Arc<Cached>, u64)>,
    tick: u64,
}

impl CertCache {
    fn new() -> CertCache {
        CertCache {
            map: HashMap::new(),
            tick: 0,
        }
    }

    fn get(&mut self, host: &str) -> Option<Arc<Cached>> {
        self.tick += 1;
        let tick = self.tick;
        let entry = self.map.get_mut(host)?;
        entry.1 = tick;
        Some(Arc::clone(&entry.0))
    }

    fn put(&mut self, host: &str, value: Arc<Cached>) {
        self.tick += 1;
        let tick = self.tick;
        if !self.map.contains_key(host)
            && self.map.len() >= CACHE_MAX
            && let Some(lru) = self
                .map
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
        {
            self.map.remove(&lru);
        }
        self.map.insert(host.to_owned(), (value, tick));
    }
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
    cache: Mutex<CertCache>,
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// host → earliest Unix time we may retry issuance after a recent failure.
    failures: Mutex<HashMap<String, u64>>,
    /// Number of issuances currently talking to the CA (bounded by `MAX_INFLIGHT`).
    in_flight: AtomicUsize,
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
                cache: Mutex::new(CertCache::new()),
                locks: Mutex::new(HashMap::new()),
                failures: Mutex::new(HashMap::new()),
                in_flight: AtomicUsize::new(0),
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

    /// The host to route a connection by: its SNI when present, otherwise the
    /// configured [`default_host`](AcmeConfig::default_host). `None` means there
    /// is no usable host, so the caller should serve the self-signed fallback.
    fn effective_host(&self, sni: Option<&str>) -> Option<String> {
        if let Some(h) = sni.map(normalize).filter(|h| !h.is_empty()) {
            return Some(h);
        }
        self.inner
            .cfg
            .default_host
            .as_deref()
            .map(normalize)
            .filter(|h| !h.is_empty())
    }

    /// Decide which certificate to present for a connection.
    pub fn choose(&self, sni: Option<&str>, peer_is_loopback: bool) -> CertChoice {
        // Loopback never gets a public cert — there's nothing a CA could verify.
        if peer_is_loopback {
            return CertChoice::Serve(self.self_signed());
        }
        let Some(host) = self.effective_host(sni) else {
            // No SNI and no default host configured: self-signed fallback.
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
        let Some(host) = self.effective_host(sni) else {
            return CertChoice::Serve(self.self_signed());
        };
        if let Some(wl) = &self.inner.cfg.host_whitelist
            && !wl.contains(&host)
        {
            return CertChoice::Reject;
        }
        if let Some(c) = self.inner.cache.lock().unwrap().get(&host) {
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
        if let Some(c) = self.inner.cache.lock().unwrap().get(host)
            && !near_expiry(c.not_after, now)
        {
            return Ok(c.acceptor.clone());
        }

        // Negative cache: a recent failure short-circuits to an error (→ Reject)
        // without re-running the blocking issuance flow, until the cooldown ends.
        if self.in_backoff(host, now) {
            return Err(Error::Acme(format!(
                "{host}: skipping issuance, backing off after a recent failure"
            )));
        }

        // Serialize issuance per host.
        let lock = self.host_lock(host);
        let result = {
            let _guard = lock.lock().unwrap();

            // Re-check the cache and backoff now that we hold the lock (another
            // waiter may have just succeeded or failed).
            if let Some(c) = self.inner.cache.lock().unwrap().get(host)
                && !near_expiry(c.not_after, now)
            {
                Ok(c.acceptor.clone())
            } else if self.in_backoff(host, now) {
                Err(Error::Acme(format!(
                    "{host}: skipping issuance, backing off after a recent failure"
                )))
            } else {
                self.try_issue(host, now)
            }
        };
        // Drop the per-host lock entry if no other waiter still references it,
        // so the lock map cannot grow without bound across distinct SNIs.
        self.release_host_lock(host, lock);
        result
    }

    /// Disk-then-CA issuance, recording negative-cache state on the outcome.
    /// Assumes the per-host lock is held.
    fn try_issue(&self, host: &str, now: u64) -> Result<TlsAcceptor> {
        // Try disk before talking to the CA.
        let stored = self.inner.store.load_cert(host)?;
        if let Some(stored) = &stored {
            let not_after = cert_not_after(&stored.chain_pem);
            if !near_expiry(not_after, now) {
                let acceptor = TlsAcceptor::from_pem(&stored.chain_pem, &stored.key_pem)?;
                self.cache_put(host, acceptor.clone(), not_after);
                self.clear_failure(host);
                return Ok(acceptor);
            }
        }

        // We are about to talk to the CA: take a global in-flight permit so the
        // number of concurrent blocking issuances stays bounded.
        let Some(_permit) = self.acquire_permit() else {
            // Transient capacity limit: shed load without backing the host off.
            return Err(Error::Acme(format!(
                "{host}: too many certificate issuances in flight, retry shortly"
            )));
        };

        match self.issue(host) {
            Ok(acceptor) => {
                self.clear_failure(host);
                Ok(acceptor)
            }
            Err(e) => {
                // Renewal failed but a still-valid cert is on disk: serve it and
                // do NOT enter backoff (we have a usable cert to present).
                if let Some(stored) = &stored {
                    let not_after = cert_not_after(&stored.chain_pem);
                    if not_after.is_some_and(|t| t > now) {
                        if cfg!(debug_assertions) {
                            eprintln!(
                                "httpsd: acme: renewal for {host} failed, serving existing: {e}"
                            );
                        }
                        let acceptor = TlsAcceptor::from_pem(&stored.chain_pem, &stored.key_pem)?;
                        self.cache_put(host, acceptor.clone(), not_after);
                        return Ok(acceptor);
                    }
                }
                // Genuine failure with no servable cert: remember it briefly.
                self.record_failure(host, now);
                Err(e)
            }
        }
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

    /// Drop the per-host lock entry once issuance completes if no other thread
    /// still references it. Holding the map mutex makes the strong-count check
    /// atomic against concurrent `host_lock` callers (they need the same mutex
    /// to clone the `Arc`). `2` = the map's copy plus the `lock` argument.
    fn release_host_lock(&self, host: &str, lock: Arc<Mutex<()>>) {
        let mut locks = self.inner.locks.lock().unwrap();
        if Arc::strong_count(&lock) == 2 {
            locks.remove(host);
        }
    }

    /// Whether `host` is within an issuance-failure cooldown. Expired entries are
    /// purged opportunistically.
    fn in_backoff(&self, host: &str, now: u64) -> bool {
        let mut failures = self.inner.failures.lock().unwrap();
        match failures.get(host).copied() {
            Some(retry_at) if retry_at > now => true,
            Some(_) => {
                failures.remove(host);
                false
            }
            None => false,
        }
    }

    /// Remember an issuance failure for `host`, bounding the map's size.
    fn record_failure(&self, host: &str, now: u64) {
        let retry_at = now.saturating_add(NEG_CACHE_COOLDOWN_SECS);
        let mut failures = self.inner.failures.lock().unwrap();
        if !failures.contains_key(host) && failures.len() >= NEG_CACHE_MAX {
            // Drop expired entries first; if still full, evict the soonest to
            // expire so the map can never grow past the cap.
            failures.retain(|_, &mut t| t > now);
            if failures.len() >= NEG_CACHE_MAX
                && let Some(oldest) = failures
                    .iter()
                    .min_by_key(|&(_, &t)| t)
                    .map(|(k, _)| k.clone())
            {
                failures.remove(&oldest);
            }
        }
        failures.insert(host.to_owned(), retry_at);
    }

    /// Clear any remembered failure for `host` (called on success).
    fn clear_failure(&self, host: &str) {
        self.inner.failures.lock().unwrap().remove(host);
    }

    /// Take a global in-flight issuance permit, or `None` if at capacity.
    fn acquire_permit(&self) -> Option<Permit<'_>> {
        let prev = self.inner.in_flight.fetch_add(1, Ordering::SeqCst);
        if prev >= MAX_INFLIGHT {
            self.inner.in_flight.fetch_sub(1, Ordering::SeqCst);
            None
        } else {
            Some(Permit {
                counter: &self.inner.in_flight,
            })
        }
    }

    fn cache_put(&self, host: &str, acceptor: TlsAcceptor, not_after: Option<u64>) {
        self.inner.cache.lock().unwrap().put(
            host,
            Arc::new(Cached {
                acceptor,
                not_after,
            }),
        );
    }
}

/// RAII guard for a global in-flight issuance permit.
struct Permit<'a> {
    counter: &'a AtomicUsize,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
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
        // Unknown expiry: treat as needing renewal rather than never-expiring,
        // so a cert whose `notAfter` can't be parsed isn't served forever.
        None => true,
    }
}

/// Parse the leaf certificate's `notAfter` (Unix seconds) from a chain PEM.
fn cert_not_after(chain_pem: &str) -> Option<u64> {
    // A fullchain PEM holds several certificates (leaf + intermediates), and
    // `Certificate::from_pem` rejects the trailing blocks (`Der(Pem)`). Parse
    // only the leaf — the first block — which is the cert whose expiry we renew
    // against. Without this the expiry is unknown, and `near_expiry(None)` is
    // `true`, so the server re-issues on every check until it is rate-limited.
    let leaf = first_pem_cert(chain_pem)?;
    let cert = Certificate::from_pem(&leaf).ok()?;
    Some(cert.validity().ok()?.not_after.to_unix())
}

/// Extract the first PEM `CERTIFICATE` block (the leaf) from a chain.
fn first_pem_cert(pem: &str) -> Option<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let start = pem.find(BEGIN)?;
    let end = pem[start..].find(END)? + start + END.len();
    Some(pem[start..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_window() {
        let now = 1_000_000_000;
        assert!(near_expiry(Some(now + 10 * 86_400), now)); // 10 days left → renew
        assert!(!near_expiry(Some(now + 60 * 86_400), now)); // 60 days left → keep
        assert!(near_expiry(None, now)); // unknown expiry → renew, don't serve forever
    }

    #[test]
    fn effective_host_falls_back_to_default_host() {
        let dir = std::env::temp_dir().join(format!("httpsd-acme-{}", std::process::id()));
        let mgr = AcmeManager::new(AcmeConfig {
            default_host: Some("Example.COM.".into()), // mixed case + trailing dot
            cert_dir: Some(dir.clone()),
            ..Default::default()
        })
        .expect("manager");

        // SNI present → route by it.
        assert_eq!(
            mgr.effective_host(Some("foo.test")).as_deref(),
            Some("foo.test")
        );
        // No SNI (or empty) → the normalized default host.
        assert_eq!(mgr.effective_host(None).as_deref(), Some("example.com"));
        assert_eq!(mgr.effective_host(Some("")).as_deref(), Some("example.com"));

        // Without a default host, no SNI → None (caller serves self-signed).
        let mgr2 = AcmeManager::new(AcmeConfig {
            cert_dir: Some(dir.clone()),
            ..Default::default()
        })
        .expect("manager");
        assert_eq!(mgr2.effective_host(None), None);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn first_pem_cert_takes_the_leaf_from_a_chain() {
        // A fullchain has several blocks; the leaf is the first. (Real cert
        // parsing is covered indirectly — the bug was that the multi-block chain
        // failed to parse at all, so `cert_not_after` saw the whole string.)
        let chain = "junk before\n\
            -----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n\
            -----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----\n";
        let leaf = first_pem_cert(chain).expect("a leaf block");
        assert!(leaf.contains("LEAF"));
        assert!(!leaf.contains("INTERMEDIATE"));
        assert!(leaf.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(leaf.trim_end().ends_with("-----END CERTIFICATE-----"));
        assert!(first_pem_cert("no pem here").is_none());
    }

    #[test]
    fn normalize_host() {
        assert_eq!(normalize(" Example.COM. "), "example.com");
    }
}
