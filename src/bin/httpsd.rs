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

    // Optionally serve HTTP/3 on UDP alongside the TCP server. It runs on its
    // own thread; the TCP server (HTTP/1.1 + HTTP/2) stays in the foreground.
    #[cfg(feature = "h3")]
    if opts.http3 {
        let h3 = opts.build_server()?;
        let addr = opts.listen.clone();
        std::thread::spawn(move || {
            if let Err(e) = h3.run_h3() {
                eprintln!("httpsd: http/3 disabled: {e}");
            }
        });
        eprintln!("httpsd: also serving HTTP/3 on udp/{addr}");
    }
    #[cfg(not(feature = "h3"))]
    if opts.http3 {
        eprintln!("httpsd: warning: built without the `h3` feature; --http3 ignored");
    }

    let server = opts.build_server()?;
    let addr = opts.listen.clone();
    let scheme = if opts.is_tls() { "https" } else { "http" };
    eprintln!("httpsd: serving on {scheme}://{addr}");
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
        --http3             also serve HTTP/3 over QUIC/UDP (requires TLS)
        --no-compress       disable response compression
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
    http3: bool,
    no_compress: bool,
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
            http3: false,
            no_compress: false,
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
                "--http3" => opts.http3 = true,
                "--workers" => {
                    let v = take_value(args, &mut i, arg)?;
                    opts.workers = Some(v.parse().map_err(|_| format!("invalid --workers: {v}"))?);
                }
                "--no-compress" => opts.no_compress = true,
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

        server = self.apply_tls(server)?;
        if self.no_compress {
            server = self.disable_compress(server);
        }
        Ok(server)
    }

    #[cfg(feature = "tls")]
    fn apply_tls(&self, server: Server) -> httpsd::Result<Server> {
        match (&self.tls_cert, &self.tls_key, &self.self_signed) {
            (Some(cert), Some(key), _) => {
                Ok(server.tls(httpsd::tls::TlsAcceptor::from_pem_files(cert, key)?))
            }
            (Some(_), None, _) | (None, Some(_), _) => {
                Err(httpsd::Error::Config("--tls-cert requires --tls-key".into()))
            }
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

/// Consume the value following a flag that expects one.
fn take_value(args: &[String], i: &mut usize, flag: &str) -> std::result::Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}
