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

#[cfg(feature = "rt-threadpool")]
mod threadpool;
#[cfg(feature = "rt-tokio")]
mod tokio;
#[cfg(feature = "rt-mio")]
mod mio;

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

    /// Run on the blocking thread-pool runtime. Blocks the calling thread.
    #[cfg(feature = "rt-threadpool")]
    pub fn run(self) -> Result<()> {
        let listener = std::net::TcpListener::bind(self.addrs.as_slice())?;
        let cfg = self.session_config();
        threadpool::run(
            listener,
            cfg,
            #[cfg(feature = "tls")]
            self.tls,
            self.workers,
        )
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
}

/// Pick a sensible default worker count from the available parallelism.
fn default_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
