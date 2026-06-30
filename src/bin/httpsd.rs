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

use httpsd::Server;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("httpsd: {e}");
            ExitCode::FAILURE
        }
    }
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

    // Serve HTTP/3 on UDP alongside the TCP server by default whenever we have a
    // static TLS certificate. It runs on its own thread; the TCP server
    // (HTTP/1.1 + HTTP/2) stays in the foreground.
    #[cfg(feature = "h3")]
    if opts.http3_enabled() {
        let h3 = opts.build_server()?;
        let addr = opts.listen.clone();
        std::thread::spawn(move || {
            if let Err(e) = h3.run_h3() {
                eprintln!("httpsd: http/3 disabled: {e}");
            }
        });
        eprintln!("httpsd: also serving HTTP/3 on udp/{addr}");
    }

    let server = opts.build_server()?;
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
    server.run()
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
        --no-http3          do not serve HTTP/3 (on by default with a TLS cert)
        --http ADDR         also bind a plain-HTTP listener for redirects + ACME HTTP-01
        --allow-http        serve content over HTTP instead of redirecting to HTTPS
        --acme-accept-tos   enable automatic certificates, accepting the CA's terms of service
        --acme-email EMAIL  ACME account contact email
        --acme-directory URL  ACME directory (default Let's Encrypt production)
        --acme-staging      use the Let's Encrypt staging environment
        --host-whitelist H1,H2  only issue certificates for these hosts
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
";

struct Options {
    config: Option<String>,
    dir: String,
    listen: String,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    self_signed: Option<String>,
    workers: Option<usize>,
    no_http3: bool,
    no_compress: bool,
    allow_http: bool,
    http_listen: Option<String>,
    acme_accept_tos: bool,
    acme_email: Option<String>,
    acme_directory: Option<String>,
    acme_staging: bool,
    host_whitelist: Option<Vec<String>>,
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
            no_http3: false,
            no_compress: false,
            allow_http: false,
            http_listen: None,
            acme_accept_tos: false,
            acme_email: None,
            acme_directory: None,
            acme_staging: false,
            host_whitelist: None,
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
                "--no-compress" => opts.no_compress = true,
                "--allow-http" => opts.allow_http = true,
                "--http" => opts.http_listen = Some(take_value(args, &mut i, arg)?),
                "--acme-accept-tos" => opts.acme_accept_tos = true,
                "--acme-email" => opts.acme_email = Some(take_value(args, &mut i, arg)?),
                "--acme-directory" => opts.acme_directory = Some(take_value(args, &mut i, arg)?),
                "--acme-staging" => opts.acme_staging = true,
                "--cert-dir" => opts.cert_dir = Some(take_value(args, &mut i, arg)?),
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

    fn build_server(&self) -> httpsd::Result<Server> {
        // A config file takes over completely.
        if let Some(path) = &self.config {
            return httpsd::ServerConfig::from_file(path)?.into_server();
        }

        let mut server = Server::bind(self.listen.as_str())?.serve_dir(self.dir.clone());
        if let Some(workers) = self.workers {
            server = server.workers(workers);
        }
        if self.no_server_header {
            server = server.server_name(None);
        } else if let Some(name) = &self.server_name {
            server = server.server_name(Some(name.clone()));
        }

        server = self.apply_tls(server)?;
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
        server = self.apply_acme(server)?;
        // Advertise HTTP/3 via Alt-Svc when we'll be serving it.
        #[cfg(feature = "h3")]
        if self.http3_enabled() {
            let port = self.listen_port();
            server = server.alt_svc(Some(format!("h3=\":{port}\"; ma=86400")));
        }
        Ok(server)
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
            || self.cert_dir.is_some()
    }

    #[cfg(feature = "acme")]
    fn apply_acme(&self, server: Server) -> httpsd::Result<Server> {
        if !self.acme_requested() {
            return Ok(server);
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
        let whitelist = self.host_whitelist.as_ref().map(|hosts| {
            hosts
                .iter()
                .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
                .collect()
        });
        let cfg = httpsd::acme::AcmeConfig {
            directory_url: directory,
            accept_tos: true,
            email: self.acme_email.clone(),
            host_whitelist: whitelist,
            cert_dir: self.cert_dir.clone().map(std::path::PathBuf::from),
        };
        Ok(server.acme(httpsd::acme::AcmeManager::new(cfg)?))
    }

    #[cfg(not(feature = "acme"))]
    fn apply_acme(&self, server: Server) -> httpsd::Result<Server> {
        if self.acme_requested() {
            return Err(httpsd::Error::Config(
                "automatic certificates requested but the `acme` feature is not enabled".into(),
            ));
        }
        Ok(server)
    }

    #[cfg(feature = "tls")]
    fn apply_tls(&self, server: Server) -> httpsd::Result<Server> {
        match (&self.tls_cert, &self.tls_key, &self.self_signed) {
            (Some(cert), Some(key), _) => {
                Ok(server.tls(httpsd::tls::TlsAcceptor::from_pem_files(cert, key)?))
            }
            (Some(_), None, _) | (None, Some(_), _) => Err(httpsd::Error::Config(
                "--tls-cert requires --tls-key".into(),
            )),
            (None, None, Some(host)) => {
                Ok(server.tls(httpsd::tls::TlsAcceptor::self_signed(&[host.as_str()])?))
            }
            (None, None, None) => Ok(server),
        }
    }

    #[cfg(not(feature = "tls"))]
    fn apply_tls(&self, server: Server) -> httpsd::Result<Server> {
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

    #[cfg(feature = "h3")]
    let h3_on = opts.http3_enabled();
    #[cfg(not(feature = "h3"))]
    let h3_on = false;
    let expected = 1 + usize::from(h3_on);

    let mut handles: Vec<std::thread::JoinHandle<httpsd::Result<()>>> = Vec::new();

    #[cfg(feature = "h3")]
    if h3_on {
        let h3 = opts.build_server()?.notify_bound(tx.clone());
        let addr = opts.listen.clone();
        eprintln!("httpsd: also serving HTTP/3 on udp/{addr}");
        handles.push(std::thread::spawn(move || h3.run_h3()));
    }

    let server = opts.build_server()?.notify_bound(tx.clone());
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

    // Serve. join blocks on the (forever-running) serving threads; an error is
    // surfaced if one ever returns.
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
