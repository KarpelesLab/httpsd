//! [`Session`] — the sans-I/O glue between a socket's byte stream and a response.
//!
//! A `Session` owns the [`H1Conn`] HTTP engine, an optional TLS transport, and
//! the shared [`Handler`]. Runtimes feed it the bytes that arrive on a socket
//! and write back the bytes it produces; the session takes care of decrypting,
//! parsing, invoking the handler (with optional compression), serializing, and
//! re-encrypting. It performs no I/O itself.

use std::sync::Arc;

use crate::error::Result;
use crate::handler::Handler;
use crate::proto::{H1Conn, Limits};

#[cfg(feature = "compress")]
use crate::compress;

/// The transport beneath the HTTP engine: either a plain byte passthrough or a
/// TLS layer.
enum Transport {
    Plain,
    #[cfg(feature = "tls")]
    Tls(Box<crate::tls::TlsStream>),
}

/// Shared, per-server settings a [`Session`] needs. Cheap to clone.
#[derive(Clone)]
pub struct SessionConfig {
    /// The request handler, shared across all connections.
    pub handler: Arc<dyn Handler>,
    /// HTTP parsing limits.
    pub limits: Limits,
    /// `Server` header value (or `None` to omit).
    pub server_name: Option<String>,
    /// Response compression options.
    #[cfg(feature = "compress")]
    pub compression: compress::Options,
}

impl SessionConfig {
    /// Build a config around a handler, with default limits and compression.
    pub fn new(handler: Arc<dyn Handler>) -> SessionConfig {
        SessionConfig {
            handler,
            limits: Limits::default(),
            server_name: Some(concat!("httpsd/", env!("CARGO_PKG_VERSION")).to_owned()),
            #[cfg(feature = "compress")]
            compression: compress::Options::default(),
        }
    }
}

/// A single HTTP(S) connection in progress.
pub struct Session {
    conn: H1Conn,
    transport: Transport,
    cfg: SessionConfig,
}

impl Session {
    /// Create a plaintext (HTTP) session.
    pub fn plain(cfg: SessionConfig) -> Session {
        let mut conn = H1Conn::new(cfg.limits);
        conn.set_server_name(cfg.server_name.clone());
        Session {
            conn,
            transport: Transport::Plain,
            cfg,
        }
    }

    /// Create a TLS (HTTPS) session wrapping an accepted [`TlsStream`].
    #[cfg(feature = "tls")]
    pub fn tls(cfg: SessionConfig, stream: crate::tls::TlsStream) -> Session {
        let mut conn = H1Conn::new(cfg.limits);
        conn.set_server_name(cfg.server_name.clone());
        Session {
            conn,
            transport: Transport::Tls(Box::new(stream)),
            cfg,
        }
    }

    /// Feed bytes received from the socket. Decrypts (if TLS), parses any
    /// complete requests, runs the handler, and queues serialized responses.
    pub fn received(&mut self, wire_in: &[u8]) -> Result<()> {
        let plaintext = match &mut self.transport {
            Transport::Plain => wire_in.to_vec(),
            #[cfg(feature = "tls")]
            Transport::Tls(stream) => {
                stream.feed(wire_in)?;
                stream.recv_all()?
            }
        };
        if !plaintext.is_empty() {
            self.conn.feed(&plaintext);
        }
        self.pump()
    }

    /// Run the handler for every fully-received request, serializing each reply.
    fn pump(&mut self) -> Result<()> {
        // `poll_request` yields `Ok(None)` when more bytes are needed and
        // `Err(..)` after queueing an error response (and marking close); both
        // simply end the pump.
        while let Ok(Some(req)) = self.conn.poll_request() {
            let resp = self.cfg.handler.handle(&req);
            #[cfg(feature = "compress")]
            let resp = compress::compress_response(&req, resp, &self.cfg.compression);
            self.conn.respond(resp);
        }
        Ok(())
    }

    /// Produce the bytes that should be written to the socket: TLS handshake
    /// records and/or encrypted (or plain) response data. May be empty.
    pub fn to_send(&mut self) -> Result<Vec<u8>> {
        let app = self.conn.take_out();
        match &mut self.transport {
            Transport::Plain => Ok(app),
            #[cfg(feature = "tls")]
            Transport::Tls(stream) => {
                stream.send(&app)?;
                // pop_all also drains pending handshake records, so this works
                // before any application data exists.
                stream.pop_all()
            }
        }
    }

    /// Whether the connection should be closed once all pending output has been
    /// written.
    pub fn wants_close(&self) -> bool {
        self.conn.wants_close()
    }

    /// Whether the session is mid-handshake and not yet ready for HTTP. For
    /// plaintext sessions this is always `false`.
    pub fn handshaking(&self) -> bool {
        match &self.transport {
            Transport::Plain => false,
            #[cfg(feature = "tls")]
            Transport::Tls(stream) => !stream.is_handshake_complete(),
        }
    }
}
