//! Runtime drivers: the glue that moves bytes between real sockets and the
//! sans-I/O [`Session`](crate::session::Session).
//!
//! All drivers share the same [`Server`] builder and the same protocol core;
//! they differ only in how they wait for and perform socket I/O:
//!
//! - [`Server::run`] — blocking accept loop + worker thread pool (`rt-threadpool`).
//! - [`Server::run_tokio`] — async tasks on a tokio runtime (`rt-tokio`).
//! - [`Server::run_mio`] — single-thread readiness event loop (`rt-mio`).

use std::net::ToSocketAddrs;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::handler::Handler;
use crate::proto::{Request, Response, StatusCode};
use crate::session::SessionConfig;
use crate::static_files::StaticFiles;

#[cfg(feature = "compress")]
use crate::compress;
#[cfg(feature = "tls")]
use crate::tls::TlsAcceptor;

pub(crate) mod common;
pub(crate) mod redirect;
#[cfg(feature = "acme")]
pub(crate) mod route;

#[cfg(feature = "rt-threadpool")]
mod threadpool;
#[cfg(feature = "rt-tokio")]
mod tokio;
#[cfg(feature = "rt-mio")]
mod mio;
#[cfg(feature = "h3")]
mod quic;

#[cfg(feature = "acme")]
use crate::acme::AcmeManager;

/// How the main listener terminates TLS.
#[cfg(feature = "rt-threadpool")]
pub(crate) enum TlsMode {
    /// Plain HTTP, no TLS.
    Plain,
    /// A single static certificate.
    #[cfg(feature = "tls")]
    Static(TlsAcceptor),
    /// Per-connection certificates via ACME (SNI-routed).
    #[cfg(feature = "acme")]
    Acme(AcmeManager),
}

/// A default handler used when none is configured: replies `404` to everything.
fn not_found(_req: &Request) -> Response {
    Response::status(StatusCode::NOT_FOUND)
}

/// A configured HTTP(S) server, ready to [`run`](Server::run).
///
/// Build it with [`Server::bind`], attach a [`Handler`] (or
/// [`serve_dir`](Server::serve_dir)), optionally enable TLS, then call one of
/// the `run*` methods for the runtime you compiled in.
pub struct Server {
    addrs: Vec<std::net::SocketAddr>,
    handler: Arc<dyn Handler>,
    server_name: Option<String>,
    workers: usize,
    #[cfg(feature = "tls")]
    tls: Option<TlsAcceptor>,
    #[cfg(feature = "compress")]
    compression: compress::Options,
    /// Serve content over plain HTTP instead of redirecting to HTTPS.
    allow_http: bool,
    /// Optional plain-HTTP listener address(es) for redirects + ACME HTTP-01.
    http_addrs: Vec<std::net::SocketAddr>,
    #[cfg(feature = "acme")]
    acme: Option<AcmeManager>,
}

impl Server {
    /// Resolve and remember the listen address(es). Does not bind yet.
    pub fn bind(addr: impl ToSocketAddrs) -> Result<Server> {
        let addrs: Vec<_> = addr.to_socket_addrs()?.collect();
        if addrs.is_empty() {
            return Err(Error::Config("no socket address resolved".into()));
        }
        Ok(Server {
            addrs,
            handler: Arc::new(not_found),
            server_name: Some(concat!("httpsd/", env!("CARGO_PKG_VERSION")).to_owned()),
            workers: default_workers(),
            #[cfg(feature = "tls")]
            tls: None,
            #[cfg(feature = "compress")]
            compression: compress::Options::default(),
            allow_http: false,
            http_addrs: Vec::new(),
            #[cfg(feature = "acme")]
            acme: None,
        })
    }

    /// Set the request handler.
    pub fn handler<H: Handler + 'static>(mut self, handler: H) -> Server {
        self.handler = Arc::new(handler);
        self
    }

    /// Set the request handler from an existing `Arc`.
    pub fn handler_arc(mut self, handler: Arc<dyn Handler>) -> Server {
        self.handler = handler;
        self
    }

    /// Serve static files from `root` (convenience for a [`StaticFiles`] handler).
    pub fn serve_dir(self, root: impl Into<std::path::PathBuf>) -> Server {
        self.handler(StaticFiles::new(root))
    }

    /// Set the number of worker threads for the thread-pool runtime.
    pub fn workers(mut self, workers: usize) -> Server {
        self.workers = workers.max(1);
        self
    }

    /// Set the `Server` response header value (`None` to omit it).
    pub fn server_name(mut self, name: Option<String>) -> Server {
        self.server_name = name;
        self
    }

    /// Enable TLS with the given acceptor (turns the server into HTTPS).
    #[cfg(feature = "tls")]
    pub fn tls(mut self, acceptor: TlsAcceptor) -> Server {
        self.tls = Some(acceptor);
        self
    }

    /// Configure response compression.
    #[cfg(feature = "compress")]
    pub fn compression(mut self, options: compress::Options) -> Server {
        self.compression = options;
        self
    }

    /// Serve content over plain HTTP instead of redirecting to HTTPS. Off by
    /// default — this server upgrades HTTP requests to HTTPS.
    pub fn allow_http(mut self, allow: bool) -> Server {
        self.allow_http = allow;
        self
    }

    /// Also bind a plain-HTTP listener (e.g. port 80) that redirects to HTTPS
    /// and serves ACME HTTP-01 challenges. Runs on its own thread under
    /// [`run`](Server::run).
    pub fn http_redirect(mut self, addr: impl ToSocketAddrs) -> Result<Server> {
        self.http_addrs = addr.to_socket_addrs()?.collect();
        Ok(self)
    }

    /// Enable automatic certificates via ACME, routed per-connection by SNI.
    /// Takes precedence over a static [`tls`](Server::tls) acceptor. Currently
    /// served by the thread-pool runtime ([`run`](Server::run)).
    #[cfg(feature = "acme")]
    pub fn acme(mut self, manager: AcmeManager) -> Server {
        self.acme = Some(manager);
        self
    }

    /// Build the shared session configuration.
    fn session_config(&self) -> SessionConfig {
        SessionConfig {
            handler: Arc::clone(&self.handler),
            limits: crate::proto::Limits::default(),
            server_name: self.server_name.clone(),
            #[cfg(feature = "compress")]
            compression: self.compression,
        }
    }

    /// Build the context for the plain-HTTP listener.
    fn http_ctx(&self) -> redirect::HttpCtx {
        redirect::HttpCtx {
            allow_http: self.allow_http,
            server_name: self.server_name.clone(),
            limits: crate::proto::Limits::default(),
            content: self.allow_http.then(|| Arc::clone(&self.handler)),
            #[cfg(feature = "acme")]
            acme: self.acme.clone(),
            #[cfg(feature = "compress")]
            compression: self.compression,
        }
    }

    /// Pick how the main listener terminates TLS.
    #[cfg(feature = "rt-threadpool")]
    fn tls_mode(&self) -> TlsMode {
        #[cfg(feature = "acme")]
        if let Some(mgr) = &self.acme {
            return TlsMode::Acme(mgr.clone());
        }
        #[cfg(feature = "tls")]
        if let Some(acc) = &self.tls {
            return TlsMode::Static(acc.clone());
        }
        TlsMode::Plain
    }

    /// Run on the blocking thread-pool runtime. Blocks the calling thread.
    /// If an HTTP redirect listener is configured, it runs on its own thread.
    #[cfg(feature = "rt-threadpool")]
    pub fn run(self) -> Result<()> {
        let listener = std::net::TcpListener::bind(self.addrs.as_slice())?;
        let cfg = self.session_config();
        let tls_mode = self.tls_mode();

        if !self.http_addrs.is_empty() {
            let http = std::net::TcpListener::bind(self.http_addrs.as_slice())?;
            let ctx = self.http_ctx();
            std::thread::spawn(move || threadpool::run_http_redirect(http, ctx));
        }

        threadpool::run(listener, cfg, tls_mode, self.workers)
    }

    /// Run on a tokio runtime. Requires being called from within a tokio
    /// runtime context (e.g. under `#[tokio::main]`).
    #[cfg(feature = "rt-tokio")]
    pub async fn run_tokio(self) -> Result<()> {
        let cfg = self.session_config();
        tokio::run(
            self.addrs.clone(),
            cfg,
            #[cfg(feature = "tls")]
            self.tls,
        )
        .await
    }

    /// Run on a single-thread mio readiness event loop. Blocks the calling
    /// thread.
    #[cfg(feature = "rt-mio")]
    pub fn run_mio(self) -> Result<()> {
        let cfg = self.session_config();
        mio::run(
            self.addrs.clone(),
            cfg,
            #[cfg(feature = "tls")]
            self.tls,
        )
    }

    /// Run an HTTP/3 server on a QUIC/UDP event loop, listening on the same
    /// address(es) as the TCP server (but over UDP). Requires TLS to be
    /// configured (HTTP/3 is always encrypted). Blocks the calling thread.
    #[cfg(feature = "h3")]
    pub fn run_h3(self) -> Result<()> {
        let acceptor = self
            .tls
            .clone()
            .ok_or_else(|| Error::Config("HTTP/3 requires TLS (set an acceptor via .tls())".into()))?;
        let cfg = self.session_config();
        quic::run(self.addrs.clone(), cfg, acceptor)
    }
}

/// Pick a sensible default worker count from the available parallelism.
fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
