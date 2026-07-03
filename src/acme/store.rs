//! On-disk persistence for the ACME account key and issued certificates.
//!
//! Layout under the base directory:
//! ```text
//! <base>/account.key            ACME account private key (PEM)
//! <base>/certs/<host>/fullchain.pem
//! <base>/certs/<host>/key.pem
//! ```
//!
//! Base directory resolution (first that works):
//! 1. an explicit path (CLI/config),
//! 2. `/var/lib/httpsd` — the FHS home for persistent daemon state (needs root
//!    or a pre-created writable dir),
//! 3. `$XDG_DATA_HOME/httpsd` (or `~/.local/share/httpsd`).
//!
//! **Never** `/run` (= `/var/run`): it is tmpfs and wiped on reboot, which would
//! trigger re-issuance every boot and hit CA rate limits. Directories are
//! created `0700` and key files `0600`.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// A certificate loaded from (or to be saved to) disk.
#[derive(Debug, Clone)]
pub struct StoredCert {
    /// The full chain (leaf first) as PEM.
    pub chain_pem: String,
    /// The certificate's private key as PEM.
    pub key_pem: String,
}

/// Filesystem-backed ACME state.
#[derive(Debug, Clone)]
pub struct Store {
    base: PathBuf,
}

impl Store {
    /// Open (creating if needed) the store at `dir`, or at the default location
    /// when `dir` is `None`.
    pub fn open(dir: Option<PathBuf>) -> Result<Store> {
        let base = match dir {
            Some(d) => d,
            None => default_base()?,
        };
        create_dir_secure(&base)?;
        let store = Store { base };
        create_dir_secure(&store.certs_dir())?;
        Ok(store)
    }

    /// The base directory in use.
    pub fn base(&self) -> &Path {
        &self.base
    }

    fn certs_dir(&self) -> PathBuf {
        self.base.join("certs")
    }

    fn account_path(&self) -> PathBuf {
        self.base.join("account.key")
    }

    fn host_dir(&self, host: &str) -> Result<PathBuf> {
        Ok(self.certs_dir().join(sanitize_host(host)?))
    }

    /// Load the ACME account key PEM, or `None` if no account exists yet.
    pub fn load_account_key(&self) -> Result<Option<String>> {
        read_opt(&self.account_path())
    }

    /// Persist the ACME account key PEM (mode 0600).
    pub fn save_account_key(&self, pem: &str) -> Result<()> {
        write_secure(&self.account_path(), pem.as_bytes())
    }

    /// Load a stored certificate for `host`, or `None` if absent.
    pub fn load_cert(&self, host: &str) -> Result<Option<StoredCert>> {
        let dir = self.host_dir(host)?;
        match (
            read_opt(&dir.join("fullchain.pem"))?,
            read_opt(&dir.join("key.pem"))?,
        ) {
            (Some(chain_pem), Some(key_pem)) => Ok(Some(StoredCert { chain_pem, key_pem })),
            _ => Ok(None),
        }
    }

    /// Persist a certificate + key for `host` (chain 0644, key 0600).
    pub fn save_cert(&self, host: &str, chain_pem: &str, key_pem: &str) -> Result<()> {
        let dir = self.host_dir(host)?;
        create_dir_secure(&dir)?;
        write_public(&dir.join("fullchain.pem"), chain_pem.as_bytes())?;
        write_secure(&dir.join("key.pem"), key_pem.as_bytes())?;
        Ok(())
    }
}

/// Resolve the default base directory, preferring `/var/lib/httpsd`.
fn default_base() -> Result<PathBuf> {
    let system = PathBuf::from("/var/lib/httpsd");
    if create_dir_secure(&system).is_ok() {
        return Ok(system);
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME").filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(xdg).join("httpsd"));
    }
    if let Some(home) = std::env::var_os("HOME").filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(home).join(".local/share/httpsd"));
    }
    Err(Error::Config(
        "cannot determine a cert storage directory (set one explicitly, or HOME/XDG_DATA_HOME)"
            .into(),
    ))
}

/// Reject host names that could escape the certs directory or be ambiguous.
/// Wildcards are stored with `*` mapped to `_`.
fn sanitize_host(host: &str) -> Result<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err(Error::Config("invalid host for cert storage".into()));
    }
    let ok = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'*')
    });
    if !ok {
        return Err(Error::Config("invalid host for cert storage".into()));
    }
    Ok(host.replace('*', "_"))
}

fn read_opt(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Create a directory (and parents) with mode 0700.
fn create_dir_secure(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    set_mode(dir, 0o700)?;
    Ok(())
}

/// Atomically write a private file (mode 0600).
fn write_secure(path: &Path, data: &[u8]) -> Result<()> {
    atomic_write(path, data, 0o600)
}

/// Atomically write a world-readable file (mode 0644) — e.g. the cert chain.
fn write_public(path: &Path, data: &[u8]) -> Result<()> {
    atomic_write(path, data, 0o644)
}

fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    // A per-call unique, hard-to-predict temp name in the *same* directory as the
    // target (so `rename` stays atomic). There is no random source here, so we
    // combine the pid with a process-wide counter. The name must vary across
    // retries because we create the file with O_EXCL below.
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!("{file_name}.{}.{n}.tmp", std::process::id()));

    let result = (|| -> Result<()> {
        // Create the temp file atomically with the target mode and O_EXCL, so a
        // private key never exists on disk with a wider mode even briefly, and so
        // an existing symlink at `tmp` is refused rather than followed.
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true) // O_EXCL: refuse to follow/overwrite an existing path
                .mode(mode)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;

        // `mode` above is still masked by umask, so force the exact bits.
        set_mode(&tmp, mode)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();

    // On any error, best-effort remove the temp file so a later O_EXCL create
    // with the same name isn't wedged by a stale leftover.
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("httpsd-store-{}-{}-{}", std::process::id(), tag, n));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn account_round_trip() {
        let s = Store::open(Some(tmpdir("acct"))).unwrap();
        assert!(s.load_account_key().unwrap().is_none());
        s.save_account_key("KEYPEM").unwrap();
        assert_eq!(s.load_account_key().unwrap().as_deref(), Some("KEYPEM"));
    }

    #[test]
    fn cert_round_trip() {
        let s = Store::open(Some(tmpdir("cert"))).unwrap();
        assert!(s.load_cert("example.com").unwrap().is_none());
        s.save_cert("Example.COM.", "CHAIN", "KEY").unwrap();
        let c = s.load_cert("example.com").unwrap().unwrap();
        assert_eq!(c.chain_pem, "CHAIN");
        assert_eq!(c.key_pem, "KEY");
    }

    #[test]
    fn rejects_path_traversal_hosts() {
        let s = Store::open(Some(tmpdir("bad"))).unwrap();
        assert!(s.host_dir("../etc").is_err());
        assert!(s.host_dir("a/b").is_err());
        assert!(s.host_dir("").is_err());
        assert!(s.host_dir("ok.example.com").is_ok());
        // wildcard maps to underscore
        assert!(
            s.host_dir("*.example.com")
                .unwrap()
                .ends_with("_.example.com")
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let s = Store::open(Some(tmpdir("perm"))).unwrap();
        s.save_account_key("K").unwrap();
        let mode = std::fs::metadata(s.account_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn cert_chain_is_0644() {
        use std::os::unix::fs::PermissionsExt;
        let s = Store::open(Some(tmpdir("perm-pub"))).unwrap();
        s.save_cert("example.com", "CHAIN", "KEY").unwrap();
        let dir = s.host_dir("example.com").unwrap();
        let chain_mode = std::fs::metadata(dir.join("fullchain.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let key_mode = std::fs::metadata(dir.join("key.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(chain_mode, 0o644);
        assert_eq!(key_mode, 0o600);
    }

    #[test]
    fn atomic_write_leaves_no_tmp() {
        // A successful write must clean up after itself (the tmp file is renamed
        // into place, not left behind), and repeated writes must keep working —
        // O_EXCL with a stale leftover would otherwise wedge the second write.
        let base = tmpdir("atomic");
        std::fs::create_dir_all(&base).unwrap();
        let target = base.join("account.key");
        atomic_write(&target, b"one", 0o600).unwrap();
        atomic_write(&target, b"two", 0o600).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "two");
        let leftovers: Vec<_> = std::fs::read_dir(&base)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "stale tmp files left behind: {leftovers:?}"
        );
    }
}
