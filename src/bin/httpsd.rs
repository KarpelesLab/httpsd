//! The `httpsd` command-line server.
//!
//! Usage:
//!
//! ```text
//! httpsd [DIR]                 serve DIR (default: current directory) over HTTP
//! httpsd -c CONFIG.toml        run from a TOML configuration file
//!
//! Options:
//!   -c, --config FILE          load configuration from FILE (other flags ignored)
//!   -l, --listen ADDR          listen address (default 127.0.0.1:8080)
//!       --tls-cert FILE        PEM certificate chain (enables HTTPS)
//!       --tls-key FILE         PEM private key
//!       --self-signed [HOST]   generate a self-signed cert (default host: localhost)
//!       --workers N            worker thread count
//!       --no-compress          disable response compression
//!   -h, --help                 print this help
//! ```

use std::process::ExitCode;

use httpsd::{ReloadHandle, Server};

/// The shared ACME manager passed around the CLI. When the `acme` feature is
/// off it degrades to `Option<()>` so the same plumbing compiles either way.
#[cfg(feature = "acme")]
type AcmeShared = Option<httpsd::acme::AcmeManager>;
#[cfg(not(feature = "acme"))]
type AcmeShared = Option<()>;

/// The shared reloadable static-TLS acceptor passed around the CLI. When the
/// `tls` feature is off it degrades to `Option<()>` so the plumbing compiles
/// either way. A single cell is shared between the TCP and HTTP/3 servers so one
/// SIGHUP reload updates both.
#[cfg(feature = "tls")]
type TlsShared = Option<httpsd::tls::ReloadableAcceptor>;
#[cfg(not(feature = "tls"))]
type TlsShared = Option<()>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("httpsd: {e}");
            ExitCode::FAILURE
        }
    }
}

use std::sync::atomic::{AtomicBool, Ordering};

/// Set by the SIGTERM/SIGINT handler; observed by the watcher thread, which then
/// triggers the graceful [`httpsd::Shutdown`].
static SHUTDOWN_REQ: AtomicBool = AtomicBool::new(false);
/// Set by the SIGHUP handler; observed (and cleared) by the watcher thread,
/// which then reloads the ACME certificate cache.
static RELOAD_REQ: AtomicBool = AtomicBool::new(false);

/// Signal handler. Runs in async-signal context, so it does ONLY
/// async-signal-safe work: atomic stores (no allocation, no locks, no I/O).
#[cfg(all(unix, feature = "privdrop"))]
extern "C" fn handle_signal(sig: libc::c_int) {
    match sig {
        libc::SIGTERM | libc::SIGINT => SHUTDOWN_REQ.store(true, Ordering::SeqCst),
        libc::SIGHUP => RELOAD_REQ.store(true, Ordering::SeqCst),
        _ => {}
    }
}

/// Install handlers for SIGTERM, SIGINT (graceful shutdown) and SIGHUP (reload).
/// `libc` is available whenever `privdrop` is (and the CLI binary always pulls
/// `privdrop` in via the `cli` feature), so this is the real implementation for
/// every CLI build; the no-op fallback below covers any exotic feature combo.
#[cfg(all(unix, feature = "privdrop"))]
fn install_signal_handlers() {
    // SAFETY: `sigaction` with a valid, initialized `struct sigaction` whose
    // `sa_sigaction` points at our `extern "C"` handler. The handler only does
    // atomic stores, which are async-signal-safe. `SA_RESTART` transparently
    // restarts interrupted syscalls, which the accept/poll loops tolerate.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handle_signal as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART;
        for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaction(sig, &action, std::ptr::null_mut());
        }
    }
}

/// No-op fallback when `libc` is unavailable (e.g. `privdrop` disabled) or on a
/// non-Unix target: the server simply runs without signal-driven shutdown.
#[cfg(not(all(unix, feature = "privdrop")))]
fn install_signal_handlers() {}

/// Spawn the watcher thread that owns the shutdown handle and the servers'
/// [`ReloadHandle`]s. It polls the signal flags every ~100ms, triggers graceful
/// shutdown on SIGTERM/SIGINT (then exits), and reloads certificates on SIGHUP.
///
/// The handles uniformly cover the CLI-flag static-cert case, ACME, and config
/// mode: each server contributes a handle regardless of how its certificates are
/// sourced, so one SIGHUP clears the ACME cache and re-reads any static cert
/// files across every listener.
fn spawn_signal_watcher(shutdown: httpsd::Shutdown, handles: Vec<ReloadHandle>) {
    use std::time::Duration;
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(100));
            if SHUTDOWN_REQ.load(Ordering::SeqCst) {
                shutdown.trigger();
                break;
            }
            if RELOAD_REQ.swap(false, Ordering::SeqCst) {
                // Reload every handle; log per-handle errors but keep going so a
                // single failed re-read does not skip the others. Reloading the
                // shared ACME manager or acceptor more than once is idempotent.
                for handle in &handles {
                    if let Err(e) = handle.reload() {
                        eprintln!("httpsd: reload error: {e}");
                    }
                }
                eprintln!("httpsd: reloaded (SIGHUP): certificates reloaded");
            }
        }
    });
}

fn run() -> httpsd::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let opts = match Options::parse(&args) {
        Ok(Some(opts)) => opts,
        Ok(None) => {
            print!("{HELP}");
            return Ok(());
        }
        Err(msg) => {
            eprintln!("httpsd: {msg}\n");
            print!("{HELP}");
            return Err(httpsd::Error::Config(msg));
        }
    };

    // Privilege dropping changes the orchestration: every privileged bind (the
    // main TCP listener, any HTTP redirect listener, and the HTTP/3 UDP socket)
    // must complete before the process-wide `setuid` runs. When requested we hand
    // off to a coordinator that binds on threads, waits for all of them, drops,
    // then blocks on the serving threads.
    #[cfg(feature = "privdrop")]
    if let Some(priv_drop) = opts.resolve_privdrop()? {
        return run_with_privdrop(&opts, priv_drop);
    }
    #[cfg(not(feature = "privdrop"))]
    if opts.user.is_some() || opts.chroot.is_some() {
        return Err(httpsd::Error::Config(
            "--user/--chroot require the `privdrop` feature (not enabled in this build)".into(),
        ));
    }

    // One graceful-shutdown handle, one shared ACME manager, and one shared
    // reloadable static-TLS acceptor, threaded into every server (TCP + HTTP/3)
    // so a SIGHUP reload clears the single cache / re-reads the single cert cell
    // and a SIGTERM/SIGINT drains every listener.
    let shutdown = httpsd::Shutdown::new();
    let acme = build_acme_shared(&opts)?;
    let tls = build_reloadable_tls_shared(&opts)?;

    // Collect each server's reload handle so the SIGHUP watcher can reload every
    // certificate source (static files + ACME cache) uniformly.
    let mut reload_handles: Vec<ReloadHandle> = Vec::new();

    // Serve HTTP/3 on UDP alongside the TCP server by default whenever we have a
    // static TLS certificate. It runs on its own thread; the TCP server
    // (HTTP/1.1 + HTTP/2) stays in the foreground.
    #[cfg(feature = "h3")]
    if opts.http3_enabled() {
        let h3 = opts.build_server(&acme, &tls, &shutdown)?;
        reload_handles.push(h3.reload_handle());
        let addr = opts.listen.clone();
        std::thread::spawn(move || {
            if let Err(e) = h3.run_h3() {
                eprintln!("httpsd: http/3 disabled: {e}");
            }
        });
        eprintln!("httpsd: also serving HTTP/3 on udp/{addr}");
    }

    let server = opts.build_server(&acme, &tls, &shutdown)?;
    reload_handles.push(server.reload_handle());
    let addr = opts.listen.clone();
    let scheme = if opts.is_tls() || opts.acme_accept_tos {
        "https"
    } else {
        "http"
    };
    eprintln!("httpsd: serving on {scheme}://{addr}");
    if let Some(http) = &opts.http_listen {
        eprintln!("httpsd: redirecting HTTP→HTTPS on {http}");
    }

    // Install signal handlers and start the watcher before serving, so a signal
    // arriving during startup is still honored.
    install_signal_handlers();
    spawn_signal_watcher(shutdown, reload_handles);

    server.run()
}

/// Build the shared ACME manager if the `acme` feature is on, else `None`.
/// Kept feature-agnostic so the same call site works either way.
#[cfg(feature = "acme")]
fn build_acme_shared(opts: &Options) -> httpsd::Result<AcmeShared> {
    opts.build_acme_manager()
}
#[cfg(not(feature = "acme"))]
fn build_acme_shared(opts: &Options) -> httpsd::Result<AcmeShared> {
    // Surface the same "acme not enabled" error the old apply_acme did.
    if opts.acme_requested() {
        return Err(httpsd::Error::Config(
            "automatic certificates requested but the `acme` feature is not enabled".into(),
        ));
    }
    Ok(None)
}

/// Build the one shared reloadable static-TLS acceptor for the CLI-flag
/// `--tls-cert`/`--tls-key` case, if any, so the TCP and HTTP/3 servers share a
/// single cell and one SIGHUP reload updates both. Kept feature-agnostic so the
/// same call site works either way.
#[cfg(feature = "tls")]
fn build_reloadable_tls_shared(opts: &Options) -> httpsd::Result<TlsShared> {
    opts.build_reloadable_tls()
}
#[cfg(not(feature = "tls"))]
fn build_reloadable_tls_shared(_opts: &Options) -> httpsd::Result<TlsShared> {
    Ok(None)
}

const HELP: &str = "\
httpsd — a pure-Rust HTTP/HTTPS server

USAGE:
    httpsd [DIR]
    httpsd -c CONFIG.toml

OPTIONS:
    -c, --config FILE       load a TOML configuration file (other flags ignored)
    -l, --listen ADDR       listen address (default 127.0.0.1:8080)
        --tls-cert FILE     PEM certificate chain, leaf first (enables HTTPS)
        --tls-key FILE      PEM private key
        --self-signed[=H]   generate a self-signed certificate (default host localhost)
        --workers N         number of worker threads
        --max-conns-per-ip N  cap concurrent connections per client IP (0 = unlimited)
        --no-http3          do not serve HTTP/3 (on by default with a TLS cert)
        --http ADDR         also bind a plain-HTTP listener for redirects + ACME HTTP-01
        --allow-http        serve content over HTTP instead of redirecting to HTTPS
        --acme-accept-tos   enable automatic certificates, accepting the CA's terms of service
        --acme-email EMAIL  ACME account contact email
        --acme-directory URL  ACME directory (default Let's Encrypt production)
        --acme-staging      use the Let's Encrypt staging environment
        --host-whitelist H1,H2  only issue certificates for these hosts
        --default-host HOST  serve this host's certificate when a client sends no SNI
        --cert-dir DIR      certificate storage directory
        --hsts              send Strict-Transport-Security (max-age 1 year) on HTTPS
        --hsts-max-age N    HSTS max-age in seconds (implies --hsts)
        --hsts-include-subdomains  add includeSubDomains (implies --hsts)
        --hsts-preload      add preload (implies --hsts)
        --no-compress       disable response compression
        --server-name NAME  set a custom Server: response header
        --no-server-header  omit the Server: response header (wins over --server-name)
        --user NAME[:GROUP] drop to this user (and group) after binding; NAME/GROUP may be numeric
        --chroot DIR        chroot into DIR after binding, before dropping privileges
    -h, --help              print this help

SIGNALS (Unix):
    SIGTERM/SIGINT          graceful shutdown (stop accepting, drain in-flight)
    SIGHUP                  reload certificates (ACME cache + static cert files)
";

struct Options {
    config: Option<String>,
    dir: String,
    listen: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    self_signed: Option<String>,
    workers: Option<usize>,
    max_conns_per_ip: Option<u32>,
    no_http3: bool,
    no_compress: bool,
    allow_http: bool,
    http_listen: Option<String>,
    acme_accept_tos: bool,
    acme_email: Option<String>,
    acme_directory: Option<String>,
    acme_staging: bool,
    host_whitelist: Option<Vec<String>>,
    default_host: Option<String>,
    cert_dir: Option<String>,
    hsts: bool,
    hsts_max_age: Option<u64>,
    hsts_include_subdomains: bool,
    hsts_preload: bool,
    server_name: Option<String>,
    no_server_header: bool,
    user: Option<String>,
    chroot: Option<String>,
}

impl Options {
    fn parse(args: &[String]) -> std::result::Result<Option<Options>, String> {
        let mut opts = Options {
            config: None,
            dir: ".".to_owned(),
            listen: "127.0.0.1:8080".to_owned(),
            tls_cert: None,
            tls_key: None,
            self_signed: None,
            workers: None,
            max_conns_per_ip: None,
            no_http3: false,
            no_compress: false,
            allow_http: false,
            http_listen: None,
            acme_accept_tos: false,
            acme_email: None,
            acme_directory: None,
            acme_staging: false,
            host_whitelist: None,
            default_host: None,
            cert_dir: None,
            hsts: false,
            hsts_max_age: None,
            hsts_include_subdomains: false,
            hsts_preload: false,
            server_name: None,
            no_server_header: false,
            user: None,
            chroot: None,
        };
        let mut saw_dir = false;
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            match arg.as_str() {
                "-h" | "--help" => return Ok(None),
                "-c" | "--config" => {
                    opts.config = Some(take_value(args, &mut i, arg)?);
                }
                "-l" | "--listen" => {
                    opts.listen = take_value(args, &mut i, arg)?;
                }
                "--tls-cert" => opts.tls_cert = Some(take_value(args, &mut i, arg)?),
                "--tls-key" => opts.tls_key = Some(take_value(args, &mut i, arg)?),
                "--self-signed" => opts.self_signed = Some("localhost".to_owned()),
                "--no-http3" => opts.no_http3 = true,
                "--workers" => {
                    let v = take_value(args, &mut i, arg)?;
                    opts.workers = Some(v.parse().map_err(|_| format!("invalid --workers: {v}"))?);
                }
                "--max-conns-per-ip" => {
                    let v = take_value(args, &mut i, arg)?;
                    opts.max_conns_per_ip = Some(
                        v.parse()
                            .map_err(|_| format!("invalid --max-conns-per-ip: {v}"))?,
                    );
                }
                "--no-compress" => opts.no_compress = true,
                "--allow-http" => opts.allow_http = true,
                "--http" => opts.http_listen = Some(take_value(args, &mut i, arg)?),
                "--acme-accept-tos" => opts.acme_accept_tos = true,
                "--acme-email" => opts.acme_email = Some(take_value(args, &mut i, arg)?),
                "--acme-directory" => opts.acme_directory = Some(take_value(args, &mut i, arg)?),
                "--acme-staging" => opts.acme_staging = true,
                "--cert-dir" => opts.cert_dir = Some(take_value(args, &mut i, arg)?),
                "--default-host" => opts.default_host = Some(take_value(args, &mut i, arg)?),
                "--hsts" => opts.hsts = true,
                "--hsts-include-subdomains" => opts.hsts_include_subdomains = true,
                "--hsts-preload" => opts.hsts_preload = true,
                "--hsts-max-age" => {
                    let v = take_value(args, &mut i, arg)?;
                    opts.hsts_max_age = Some(
                        v.parse()
                            .map_err(|_| format!("invalid --hsts-max-age: {v}"))?,
                    );
                }
                "--server-name" => opts.server_name = Some(take_value(args, &mut i, arg)?),
                "--no-server-header" => opts.no_server_header = true,
                "--user" => opts.user = Some(take_value(args, &mut i, arg)?),
                "--chroot" => opts.chroot = Some(take_value(args, &mut i, arg)?),
                "--host-whitelist" => {
                    let v = take_value(args, &mut i, arg)?;
                    opts.host_whitelist = Some(
                        v.split(',')
                            .map(|s| s.trim().to_owned())
                            .filter(|s| !s.is_empty())
                            .collect(),
                    );
                }
                other if other.starts_with("--self-signed=") => {
                    opts.self_signed = Some(other["--self-signed=".len()..].to_owned());
                }
                other if other.starts_with("--listen=") => {
                    opts.listen = other["--listen=".len()..].to_owned();
                }
                other if other.starts_with('-') && other != "-" => {
                    return Err(format!("unknown option: {other}"));
                }
                other => {
                    if saw_dir {
                        return Err(format!("unexpected argument: {other}"));
                    }
                    opts.dir = other.to_owned();
                    saw_dir = true;
                }
            }
            i += 1;
        }
        Ok(Some(opts))
    }

    fn is_tls(&self) -> bool {
        self.tls_cert.is_some() || self.self_signed.is_some()
    }

    fn build_server(
        &self,
        acme: &AcmeShared,
        tls: &TlsShared,
        shutdown: &httpsd::Shutdown,
    ) -> httpsd::Result<Server> {
        // A config file takes over completely. Its static certs are already made
        // reloadable inside `into_server`, so its `reload_handle()` covers them.
        if let Some(path) = &self.config {
            return Ok(httpsd::ServerConfig::from_file(path)?
                .into_server()?
                .graceful(shutdown.clone()));
        }

        let mut server = Server::bind(self.listen.as_str())?.serve_dir(self.dir.clone());
        if let Some(workers) = self.workers {
            server = server.workers(workers);
        }
        if let Some(n) = self.max_conns_per_ip {
            server = server.max_conns_per_ip(n);
        }
        if self.no_server_header {
            server = server.server_name(None);
        } else if let Some(name) = &self.server_name {
            server = server.server_name(Some(name.clone()));
        }

        server = self.apply_tls(server, tls)?;
        if self.no_compress {
            server = self.disable_compress(server);
        }
        if let Some(value) = self.hsts_value() {
            server = server.hsts(Some(value));
        }
        if self.allow_http {
            server = server.allow_http(true);
        }
        if let Some(http) = &self.http_listen {
            server = server.http_redirect(http.as_str())?;
        }
        server = self.apply_acme(server, acme)?;
        // Advertise HTTP/3 via Alt-Svc when we'll be serving it.
        #[cfg(feature = "h3")]
        if self.http3_enabled() {
            let port = self.listen_port();
            server = server.alt_svc(Some(format!("h3=\":{port}\"; ma=86400")));
        }
        Ok(server.graceful(shutdown.clone()))
    }

    /// Whether HTTP/3 should run: on by default whenever HTTPS is served (a
    /// static cert or ACME), off via `--no-http3`.
    #[cfg(feature = "h3")]
    fn http3_enabled(&self) -> bool {
        !self.no_http3 && (self.is_tls() || self.acme_accept_tos)
    }

    /// The port from the listen address (defaults to 443 if unparseable).
    #[cfg(feature = "h3")]
    fn listen_port(&self) -> u16 {
        self.listen
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(443)
    }

    /// Build the HSTS header value if any `--hsts*` flag was given.
    fn hsts_value(&self) -> Option<String> {
        let on = self.hsts
            || self.hsts_max_age.is_some()
            || self.hsts_include_subdomains
            || self.hsts_preload;
        if !on {
            return None;
        }
        let mut v = format!("max-age={}", self.hsts_max_age.unwrap_or(31_536_000));
        if self.hsts_include_subdomains {
            v.push_str("; includeSubDomains");
        }
        if self.hsts_preload {
            v.push_str("; preload");
        }
        Some(v)
    }

    /// Resolve the requested privilege drop, if any. A config file's
    /// `[privdrop]` table takes precedence; otherwise the `--user`/`--chroot`
    /// flags are used. Returns `None` when no drop was requested.
    #[cfg(feature = "privdrop")]
    fn resolve_privdrop(&self) -> httpsd::Result<Option<httpsd::privdrop::PrivDrop>> {
        if let Some(path) = &self.config {
            let cfg = httpsd::ServerConfig::from_file(path)?;
            if let Some(pd) = cfg.priv_drop()? {
                return Ok(Some(pd));
            }
        }
        if self.user.is_some() || self.chroot.is_some() {
            return Ok(Some(httpsd::privdrop::PrivDrop::parse(
                self.user.as_deref(),
                self.chroot.as_deref(),
            )?));
        }
        Ok(None)
    }

    /// Whether any ACME flag was supplied.
    fn acme_requested(&self) -> bool {
        self.acme_accept_tos
            || self.acme_email.is_some()
            || self.acme_directory.is_some()
            || self.acme_staging
            || self.host_whitelist.is_some()
            || self.default_host.is_some()
            || self.cert_dir.is_some()
    }

    /// Build the ACME manager once from the CLI options, if ACME was requested.
    /// The same manager is shared across the TCP and HTTP/3 servers so they use
    /// one certificate cache (required for SIGHUP reload to take effect, and a
    /// latent-bug fix since each `build_server` used to build its own).
    #[cfg(feature = "acme")]
    fn build_acme_manager(&self) -> httpsd::Result<Option<httpsd::acme::AcmeManager>> {
        if !self.acme_requested() {
            return Ok(None);
        }
        if !self.acme_accept_tos {
            return Err(httpsd::Error::Config(
                "automatic certificates require --acme-accept-tos (you accept the CA terms of service)".into(),
            ));
        }
        let directory = if self.acme_staging {
            httpsd::acme::client::LETSENCRYPT_STAGING.to_owned()
        } else {
            self.acme_directory
                .clone()
                .unwrap_or_else(|| httpsd::acme::client::LETSENCRYPT_PRODUCTION.to_owned())
        };
        let norm = |h: &str| h.trim().trim_end_matches('.').to_ascii_lowercase();
        let default_host = self
            .default_host
            .as_deref()
            .map(norm)
            .filter(|h| !h.is_empty());
        let whitelist = self.host_whitelist.as_ref().map(|hosts| {
            let mut set: std::collections::HashSet<String> =
                hosts.iter().map(|h| norm(h)).collect();
            // A configured default host must be issuable, so keep it whitelisted.
            if let Some(d) = &default_host {
                set.insert(d.clone());
            }
            set
        });
        let cfg = httpsd::acme::AcmeConfig {
            directory_url: directory,
            accept_tos: true,
            email: self.acme_email.clone(),
            host_whitelist: whitelist,
            default_host,
            cert_dir: self.cert_dir.clone().map(std::path::PathBuf::from),
        };
        Ok(Some(httpsd::acme::AcmeManager::new(cfg)?))
    }

    /// Attach the (already-built, shared) ACME manager to a server.
    #[cfg(feature = "acme")]
    fn apply_acme(
        &self,
        server: Server,
        acme: &Option<httpsd::acme::AcmeManager>,
    ) -> httpsd::Result<Server> {
        match acme {
            Some(mgr) => Ok(server.acme(mgr.clone())),
            None => Ok(server),
        }
    }

    #[cfg(not(feature = "acme"))]
    fn apply_acme(&self, server: Server, _acme: &Option<()>) -> httpsd::Result<Server> {
        if self.acme_requested() {
            return Err(httpsd::Error::Config(
                "automatic certificates requested but the `acme` feature is not enabled".into(),
            ));
        }
        Ok(server)
    }

    /// Build the shared reloadable acceptor for the CLI-flag `--tls-cert`/
    /// `--tls-key` case. Self-signed certs have no file backing and are attached
    /// (as fixed acceptors) directly in `apply_tls`, so they are not built here.
    #[cfg(feature = "tls")]
    fn build_reloadable_tls(&self) -> httpsd::Result<Option<httpsd::tls::ReloadableAcceptor>> {
        match (&self.tls_cert, &self.tls_key) {
            (Some(cert), Some(key)) => Ok(Some(httpsd::tls::ReloadableAcceptor::from_pem_files(
                cert, key,
            )?)),
            (Some(_), None) | (None, Some(_)) => Err(httpsd::Error::Config(
                "--tls-cert requires --tls-key".into(),
            )),
            (None, None) => Ok(None),
        }
    }

    #[cfg(feature = "tls")]
    fn apply_tls(&self, server: Server, tls: &TlsShared) -> httpsd::Result<Server> {
        // A file-backed cert was built once (shared across TCP + HTTP/3) as a
        // reloadable acceptor; attach that shared cell so one SIGHUP updates both.
        if let Some(acceptor) = tls {
            return Ok(server.tls_reloadable(acceptor.clone()));
        }
        // Otherwise fall back to a self-signed cert (no file backing, so fixed),
        // or plain HTTP. The cert+key/only-one-of validation happened in
        // `build_reloadable_tls`, so here `tls` is `None` only when neither
        // cert+key was given.
        match &self.self_signed {
            Some(host) => Ok(server.tls(httpsd::tls::TlsAcceptor::self_signed(&[host.as_str()])?)),
            None => Ok(server),
        }
    }

    #[cfg(not(feature = "tls"))]
    fn apply_tls(&self, server: Server, _tls: &TlsShared) -> httpsd::Result<Server> {
        if self.is_tls() {
            return Err(httpsd::Error::Config(
                "TLS requested but the `tls` feature is not enabled".into(),
            ));
        }
        Ok(server)
    }

    #[cfg(feature = "compress")]
    fn disable_compress(&self, server: Server) -> Server {
        server.compression(httpsd::compress::Options {
            enabled: false,
            ..Default::default()
        })
    }

    #[cfg(not(feature = "compress"))]
    fn disable_compress(&self, server: Server) -> Server {
        server
    }
}

/// Orchestrate startup with privilege dropping: bind every listener on its own
/// thread, wait for all of them, then drop privileges once (process-wide) and
/// serve. Dropping must happen only after every privileged bind completes,
/// because `setuid` affects the whole process — including the separate HTTP/3
/// server thread.
#[cfg(feature = "privdrop")]
fn run_with_privdrop(opts: &Options, priv_drop: httpsd::privdrop::PrivDrop) -> httpsd::Result<()> {
    use std::sync::mpsc;
    use std::time::Duration;

    if priv_drop.chroot.is_some() && opts.acme_accept_tos {
        eprintln!(
            "httpsd: warning: --chroot with ACME is unlikely to work (ACME needs DNS, a CA trust store, and a writable cert dir, which a bare chroot lacks)"
        );
    }

    let (tx, rx) = mpsc::channel::<()>();

    // One shutdown handle, one shared ACME manager, and one shared reloadable
    // static-TLS acceptor for every listener, built before the servers so
    // `.graceful(...)` is installed prior to spawning.
    let shutdown = httpsd::Shutdown::new();
    let acme = build_acme_shared(opts)?;
    let tls = build_reloadable_tls_shared(opts)?;

    // Collect each server's reload handle for the SIGHUP watcher.
    let mut reload_handles: Vec<ReloadHandle> = Vec::new();

    #[cfg(feature = "h3")]
    let h3_on = opts.http3_enabled();
    #[cfg(not(feature = "h3"))]
    let h3_on = false;
    let expected = 1 + usize::from(h3_on);

    let mut handles: Vec<std::thread::JoinHandle<httpsd::Result<()>>> = Vec::new();

    #[cfg(feature = "h3")]
    if h3_on {
        let h3 = opts
            .build_server(&acme, &tls, &shutdown)?
            .notify_bound(tx.clone());
        reload_handles.push(h3.reload_handle());
        let addr = opts.listen.clone();
        eprintln!("httpsd: also serving HTTP/3 on udp/{addr}");
        handles.push(std::thread::spawn(move || h3.run_h3()));
    }

    let server = opts
        .build_server(&acme, &tls, &shutdown)?
        .notify_bound(tx.clone());
    reload_handles.push(server.reload_handle());
    let addr = opts.listen.clone();
    let scheme = if opts.is_tls() || opts.acme_accept_tos {
        "https"
    } else {
        "http"
    };
    eprintln!("httpsd: serving on {scheme}://{addr}");
    if let Some(http) = &opts.http_listen {
        eprintln!("httpsd: redirecting HTTP→HTTPS on {http}");
    }
    handles.push(std::thread::spawn(move || server.run()));

    // Drop our own sender so the channel disconnects once the serving threads
    // (the only remaining senders) are gone.
    drop(tx);

    // Wait until every listener has signalled that it is bound. A healthy server
    // thread blocks forever once bound, so a thread that *finishes* early must
    // have failed before binding — surface that instead of waiting forever.
    let mut bound = 0usize;
    while bound < expected {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(()) => bound += 1,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if bound < expected && handles.iter().any(|h| h.is_finished()) {
            break;
        }
    }

    if bound < expected {
        // A listener failed to bind. Pull the error from whichever thread has
        // already exited (joining only finished handles can't block); the still
        // serving threads, if any, are torn down when the process exits with a
        // failure code, having never dropped privileges.
        let mut err = httpsd::Error::Config(
            "a listener exited before binding; refusing to drop privileges".into(),
        );
        for h in handles {
            if h.is_finished()
                && let Ok(Err(e)) = h.join()
            {
                err = e;
            }
        }
        return Err(err);
    }

    // Every listener is bound: drop privileges once, for the whole process.
    priv_drop.apply()?;
    eprintln!("httpsd: dropped privileges");

    // Now that privileges are dropped and the listeners are serving, install the
    // signal handlers and start the watcher. On SIGTERM/SIGINT it triggers the
    // shared shutdown, so the serving threads drain and exit and `join_all`
    // returns `Ok(())`; on SIGHUP it reloads every certificate source via the
    // collected handles (shared ACME cache + shared static cert files).
    install_signal_handlers();
    spawn_signal_watcher(shutdown, reload_handles);

    // Serve. join blocks on the serving threads; they return once they finish
    // draining after a shutdown request (or immediately on a fatal error).
    join_all(handles)
}

/// Join every server thread, returning the first error encountered.
#[cfg(feature = "privdrop")]
fn join_all(handles: Vec<std::thread::JoinHandle<httpsd::Result<()>>>) -> httpsd::Result<()> {
    let mut first_err = None;
    for h in handles {
        let result = match h.join() {
            Ok(r) => r,
            Err(_) => Err(httpsd::Error::Config("a server thread panicked".into())),
        };
        if let Err(e) = result
            && first_err.is_none()
        {
            first_err = Some(e);
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Consume the value following a flag that expects one.
fn take_value(args: &[String], i: &mut usize, flag: &str) -> std::result::Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}
