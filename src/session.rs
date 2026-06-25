//! [`Session`] — the sans-I/O glue between a socket's byte stream and a response.
//!
//! A `Session` owns an HTTP protocol engine (HTTP/1.x, or HTTP/2 when the TLS
//! client negotiates `h2` via ALPN), an optional TLS transport, and the shared
//! [`Handler`]. Runtimes feed it the bytes that arrive on a socket and write
//! back the bytes it produces; the session decrypts, parses, invokes the
//! handler (with optional compression), serializes, and re-encrypts. It
//! performs no I/O itself.

use std::sync::Arc;

use crate::error::Result;
use crate::handler::Handler;
use crate::proto::{H1Conn, Limits, Request, Response};

#[cfg(feature = "compress")]
use crate::compress;
#[cfg(feature = "h2")]
use crate::h2::H2Conn;

/// The transport beneath the HTTP engine: either a plain byte passthrough or a
/// TLS layer.
enum Transport {
    Plain,
    #[cfg(feature = "tls")]
    Tls(Box<crate::tls::TlsStream>),
}

impl Transport {
    /// Turn received wire bytes into plaintext (decrypting under TLS).
    fn decrypt(&mut self, wire_in: &[u8]) -> Result<Vec<u8>> {
        match self {
            Transport::Plain => Ok(wire_in.to_vec()),
            #[cfg(feature = "tls")]
            Transport::Tls(stream) => {
                stream.feed(wire_in)?;
                stream.recv_all()
            }
        }
    }

    /// Turn application bytes into wire bytes (encrypting under TLS, and
    /// flushing any pending handshake records).
    fn encrypt(&mut self, app: &[u8]) -> Result<Vec<u8>> {
        match self {
            Transport::Plain => Ok(app.to_vec()),
            #[cfg(feature = "tls")]
            Transport::Tls(stream) => {
                stream.send(app)?;
                stream.pop_all()
            }
        }
    }

    fn handshaking(&self) -> bool {
        match self {
            Transport::Plain => false,
            #[cfg(feature = "tls")]
            Transport::Tls(stream) => !stream.is_handshake_complete(),
        }
    }

    #[allow(unused)]
    fn alpn(&self) -> Option<Vec<u8>> {
        match self {
            Transport::Plain => None,
            #[cfg(feature = "tls")]
            Transport::Tls(stream) => stream.alpn_protocol(),
        }
    }
}

/// The chosen application protocol engine for a connection.
enum Engine {
    H1(H1Conn),
    #[cfg(feature = "h2")]
    H2(Box<H2Conn>),
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
    /// `Strict-Transport-Security` header value to send on **secure**
    /// connections (e.g. `"max-age=31536000"`), or `None` to omit it. Never
    /// sent over plain HTTP, where HSTS is meaningless.
    pub hsts: Option<String>,
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
            hsts: None,
            #[cfg(feature = "compress")]
            compression: compress::Options::default(),
        }
    }
}

/// A single HTTP(S) connection in progress.
pub struct Session {
    /// `None` until the protocol is known (after the TLS handshake).
    engine: Option<Engine>,
    transport: Transport,
    cfg: SessionConfig,
}

impl Session {
    /// Create a plaintext (HTTP/1.x) session.
    pub fn plain(cfg: SessionConfig) -> Session {
        let engine = Engine::H1(Self::new_h1(&cfg));
        Session {
            engine: Some(engine),
            transport: Transport::Plain,
            cfg,
        }
    }

    /// Create a TLS (HTTPS) session wrapping an accepted [`TlsStream`]. The
    /// protocol (HTTP/1.1 or HTTP/2) is chosen once ALPN is known.
    #[cfg(feature = "tls")]
    pub fn tls(cfg: SessionConfig, stream: crate::tls::TlsStream) -> Session {
        Session {
            engine: None,
            transport: Transport::Tls(Box::new(stream)),
            cfg,
        }
    }

    fn new_h1(cfg: &SessionConfig) -> H1Conn {
        let mut conn = H1Conn::new(cfg.limits);
        conn.set_server_name(cfg.server_name.clone());
        conn
    }

    /// Feed bytes received from the socket: decrypt, (lazily) select the
    /// protocol, parse requests, run the handler, and queue responses.
    pub fn received(&mut self, wire_in: &[u8]) -> Result<()> {
        let plaintext = self.transport.decrypt(wire_in)?;

        // Choose the engine once the handshake exposes the ALPN protocol.
        if self.engine.is_none() && !self.transport.handshaking() {
            self.select_engine();
        }

        if plaintext.is_empty() || self.engine.is_none() {
            return Ok(());
        }
        self.drive(&plaintext)
    }

    #[cfg(feature = "tls")]
    fn select_engine(&mut self) {
        #[cfg(feature = "h2")]
        if self.transport.alpn().as_deref() == Some(b"h2") {
            self.engine = Some(Engine::H2(Box::new(H2Conn::new(
                self.cfg.limits,
                self.cfg.server_name.clone(),
            ))));
            return;
        }
        self.engine = Some(Engine::H1(Self::new_h1(&self.cfg)));
    }

    #[cfg(not(feature = "tls"))]
    fn select_engine(&mut self) {
        self.engine = Some(Engine::H1(Self::new_h1(&self.cfg)));
    }

    fn drive(&mut self, plaintext: &[u8]) -> Result<()> {
        let secure = !matches!(self.transport, Transport::Plain);
        match self.engine.as_mut().unwrap() {
            Engine::H1(conn) => {
                conn.feed(plaintext);
                while let Ok(Some(req)) = conn.poll_request() {
                    let resp = Self::run_handler(&self.cfg, &req, secure);
                    conn.respond(resp);
                }
            }
            #[cfg(feature = "h2")]
            Engine::H2(conn) => {
                conn.received(plaintext);
                while let Some((sid, req)) = conn.poll_request() {
                    let resp = Self::run_handler(&self.cfg, &req, secure);
                    conn.respond(sid, resp);
                }
            }
        }
        Ok(())
    }

    /// Run the handler, apply response compression, and (on secure transports)
    /// the HSTS header.
    fn run_handler(cfg: &SessionConfig, req: &Request, secure: bool) -> Response {
        let resp = cfg.handler.handle(req);
        #[cfg(feature = "compress")]
        let resp = compress::compress_response(req, resp, &cfg.compression);
        apply_hsts(cfg, resp, secure)
    }

    /// Produce the bytes to write to the socket: TLS handshake records and/or
    /// (encrypted) response data. May be empty.
    pub fn to_send(&mut self) -> Result<Vec<u8>> {
        let app = match self.engine.as_mut() {
            Some(Engine::H1(conn)) => conn.take_out(),
            #[cfg(feature = "h2")]
            Some(Engine::H2(conn)) => conn.take_out(),
            None => Vec::new(),
        };
        self.transport.encrypt(&app)
    }

    /// Whether the connection should be closed once pending output is written.
    pub fn wants_close(&self) -> bool {
        match self.engine.as_ref() {
            Some(Engine::H1(conn)) => conn.wants_close(),
            #[cfg(feature = "h2")]
            Some(Engine::H2(conn)) => conn.wants_close(),
            None => false,
        }
    }

    /// Whether the session is still completing the TLS handshake.
    pub fn handshaking(&self) -> bool {
        self.transport.handshaking()
    }
}

/// Add the configured `Strict-Transport-Security` header when the connection is
/// secure. HSTS sent over plain HTTP is ignored by clients, so we never add it
/// there. Shared with the HTTP/3 engine (always secure).
pub(crate) fn apply_hsts(cfg: &SessionConfig, mut resp: Response, secure: bool) -> Response {
    if secure
        && let Some(value) = &cfg.hsts
    {
        resp.headers_mut()
            .set_if_absent("Strict-Transport-Security", value.clone());
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::StatusCode;

    fn cfg() -> SessionConfig {
        let mut c = SessionConfig::new(Arc::new(|_: &Request| Response::status(StatusCode::OK)));
        c.hsts = Some("max-age=31536000".into());
        c
    }

    #[test]
    fn hsts_added_only_on_secure() {
        let secure = apply_hsts(&cfg(), Response::status(StatusCode::OK), true);
        assert_eq!(
            secure.headers().get("strict-transport-security"),
            Some("max-age=31536000")
        );
        let plain = apply_hsts(&cfg(), Response::status(StatusCode::OK), false);
        assert!(plain.headers().get("strict-transport-security").is_none());
    }

    #[test]
    fn hsts_absent_when_unset() {
        let c = SessionConfig::new(Arc::new(|_: &Request| Response::status(StatusCode::OK)));
        let r = apply_hsts(&c, Response::status(StatusCode::OK), true);
        assert!(r.headers().get("strict-transport-security").is_none());
    }
}
