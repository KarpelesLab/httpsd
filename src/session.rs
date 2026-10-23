//! [`Session`] — the sans-I/O glue between a socket's byte stream and a response.
//!
//! A `Session` owns an HTTP protocol engine (HTTP/1.x, or HTTP/2 when the TLS
//! client negotiates `h2` via ALPN), an optional TLS transport, and the shared
//! [`Handler`]. Runtimes feed it the bytes that arrive on a socket and write
//! back the bytes it produces; the session decrypts, parses, invokes the
//! handler (with optional compression), serializes, and re-encrypts. It
//! performs no I/O itself.

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::error::Result;
use crate::handler::Handler;
use crate::proto::{ConnInfo, H1Conn, Limits, Request, Response, Waker};

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
    /// Turn received wire bytes into plaintext (decrypting under TLS). On a
    /// plain connection the bytes are returned borrowed — no copy; the engine
    /// copies them into its own input buffer.
    fn decrypt<'a>(&mut self, wire_in: &'a [u8]) -> Result<Cow<'a, [u8]>> {
        match self {
            Transport::Plain => Ok(Cow::Borrowed(wire_in)),
            #[cfg(feature = "tls")]
            Transport::Tls(stream) => {
                stream.feed(wire_in)?;
                Ok(Cow::Owned(stream.recv_all()?))
            }
        }
    }

    /// Turn application bytes into wire bytes (encrypting under TLS, and
    /// flushing any pending handshake records). Takes the buffer by value so a
    /// plain connection can hand it straight back without copying.
    fn encrypt(&mut self, app: Vec<u8>) -> Result<Vec<u8>> {
        match self {
            Transport::Plain => Ok(app),
            #[cfg(feature = "tls")]
            Transport::Tls(stream) => {
                stream.send(&app)?;
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

    /// Connection facts known to the transport (TLS parameters), on top of
    /// the given addresses.
    fn conn_info(&self, peer: Option<SocketAddr>, local: Option<SocketAddr>) -> ConnInfo {
        let info = ConnInfo::new().with_peer_addr(peer).with_local_addr(local);
        match self {
            Transport::Plain => info,
            #[cfg(feature = "tls")]
            Transport::Tls(stream) => info
                .with_secure(true)
                .with_tls_version(stream.protocol_version())
                .with_cipher_suite(stream.cipher_suite())
                .with_alpn(stream.alpn_protocol())
                .with_server_name(stream.server_name()),
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
    /// `Alt-Svc` header value advertising alternative services such as HTTP/3
    /// (e.g. `r#"h3=":443"; ma=86400"#`), or `None` to omit it.
    pub alt_svc: Option<String>,
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
            alt_svc: None,
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
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    /// Built on the first request (once TLS details are known), then shared by
    /// every request on the connection.
    conn_info: Option<Arc<ConnInfo>>,
    /// Fired when a stream body has new data; see [`Session::set_waker`].
    waker: Option<Waker>,
}

impl Session {
    /// Create a plaintext (HTTP/1.x) session.
    pub fn plain(cfg: SessionConfig) -> Session {
        let engine = Engine::H1(Self::new_h1(&cfg));
        Session {
            engine: Some(engine),
            transport: Transport::Plain,
            cfg,
            peer_addr: None,
            local_addr: None,
            conn_info: None,
            waker: None,
        }
    }

    /// Create a TLS (HTTPS) session wrapping an accepted
    /// [`TlsStream`](crate::tls::TlsStream). The protocol (HTTP/1.1 or HTTP/2)
    /// is chosen once ALPN is known.
    #[cfg(feature = "tls")]
    pub fn tls(cfg: SessionConfig, stream: crate::tls::TlsStream) -> Session {
        Session {
            engine: None,
            transport: Transport::Tls(Box::new(stream)),
            cfg,
            peer_addr: None,
            local_addr: None,
            conn_info: None,
            waker: None,
        }
    }

    /// Record the connection's peer and local socket addresses, reported to
    /// handlers through [`Request::conn`]. The bundled runtimes call this for
    /// every connection; a custom driver should call it right after creating
    /// the session.
    pub fn set_addrs(&mut self, peer: Option<SocketAddr>, local: Option<SocketAddr>) {
        self.peer_addr = peer;
        self.local_addr = local;
        self.conn_info = None;
    }

    /// Register a callback fired whenever a stream response body
    /// ([`Body::channel`](crate::Body::channel)) has new data or ends. It runs
    /// on the producer's thread, so it should only wake the driver (signal a
    /// condvar, a `mio::Waker`, a tokio `Notify`, …), which then calls
    /// [`to_send`](Self::to_send) and writes the result. Without a waker a
    /// driver must poll `to_send` while [`is_streaming`](Self::is_streaming)
    /// is true.
    pub fn set_waker(&mut self, waker: impl Fn() + Send + Sync + 'static) {
        self.waker = Some(Arc::new(waker));
    }

    /// Whether a response is streaming a body whose producer hasn't finished:
    /// more output may appear without any input from the peer. While this is
    /// true, [`to_send`](Self::to_send) returning nothing just means "not yet".
    pub fn is_streaming(&self) -> bool {
        match self.engine.as_ref() {
            Some(Engine::H1(conn)) => conn.is_streaming(),
            #[cfg(feature = "h2")]
            Some(Engine::H2(conn)) => conn.is_streaming(),
            None => false,
        }
    }

    /// The shared connection info, built on first use.
    fn conn_info(&mut self) -> Arc<ConnInfo> {
        if self.conn_info.is_none() {
            let info = self.transport.conn_info(self.peer_addr, self.local_addr);
            self.conn_info = Some(Arc::new(info));
        }
        Arc::clone(self.conn_info.as_ref().unwrap())
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
        self.drive(plaintext.as_ref())
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
        match self.engine.as_mut() {
            Some(Engine::H1(conn)) => conn.feed(plaintext),
            #[cfg(feature = "h2")]
            Some(Engine::H2(conn)) => conn.received(plaintext),
            None => return Ok(()),
        }
        self.serve_ready();
        Ok(())
    }

    /// Run the handler for every request the engine has ready.
    fn serve_ready(&mut self) {
        let secure = !matches!(self.transport, Transport::Plain);
        let info = self.conn_info();
        match self.engine.as_mut() {
            Some(Engine::H1(conn)) => {
                while let Ok(Some(mut req)) = conn.poll_request() {
                    req.set_conn_info(Arc::clone(&info));
                    let resp = Self::run_handler(&self.cfg, &req, secure, self.waker.as_ref());
                    conn.respond(resp);
                }
            }
            #[cfg(feature = "h2")]
            Some(Engine::H2(conn)) => {
                while let Some((sid, mut req)) = conn.poll_request() {
                    req.set_conn_info(Arc::clone(&info));
                    let resp = Self::run_handler(&self.cfg, &req, secure, self.waker.as_ref());
                    conn.respond(sid, resp);
                }
            }
            None => {}
        }
    }

    /// Run the handler, apply response compression, and (on secure transports)
    /// the HSTS header.
    fn run_handler(
        cfg: &SessionConfig,
        req: &Request,
        secure: bool,
        waker: Option<&Waker>,
    ) -> Response {
        let resp = cfg.handler.handle(req);
        #[cfg(feature = "compress")]
        let resp = compress::compress_response(req, resp, &cfg.compression);
        resp.body_ref().set_waker(waker);
        apply_edge_headers(cfg, resp, secure)
    }

    /// Produce the bytes to write to the socket: TLS handshake records and/or
    /// (encrypted) response data. May be empty.
    pub fn to_send(&mut self) -> Result<Vec<u8>> {
        let app = match self.engine.as_mut() {
            Some(Engine::H1(conn)) => {
                let mut out = conn.take_out();
                // HTTP/1 holds pipelined requests while a body is still being
                // sent; once it is done, serve any that are already buffered.
                if !conn.has_output() && !conn.awaiting_response() {
                    self.serve_ready();
                    if let Some(Engine::H1(conn)) = self.engine.as_mut() {
                        out.extend_from_slice(&conn.take_out());
                    }
                }
                out
            }
            #[cfg(feature = "h2")]
            Some(Engine::H2(conn)) => conn.take_out(),
            None => Vec::new(),
        };
        self.transport.encrypt(app)
    }

    /// Whether the engine still has output to produce — queued bytes or a
    /// response body (e.g. a file) being streamed in chunks. Drivers must keep
    /// calling [`to_send`](Self::to_send) while this is true before waiting for
    /// the next read or closing, so a body is flushed in full. (For a stream
    /// body that is waiting on its producer, `to_send` returns nothing; see
    /// [`is_streaming`](Self::is_streaming).)
    pub fn has_output(&self) -> bool {
        match self.engine.as_ref() {
            Some(Engine::H1(conn)) => conn.has_output(),
            #[cfg(feature = "h2")]
            Some(Engine::H2(conn)) => conn.has_output(),
            None => false,
        }
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

/// Add the configured edge headers: `Strict-Transport-Security` (secure
/// connections only — clients ignore HSTS over plain HTTP) and `Alt-Svc`
/// (e.g. advertising HTTP/3). Shared with the HTTP/3 engine (always secure).
pub(crate) fn apply_edge_headers(
    cfg: &SessionConfig,
    mut resp: Response,
    secure: bool,
) -> Response {
    let h = resp.headers_mut();
    if secure && let Some(value) = &cfg.hsts {
        h.set_if_absent("Strict-Transport-Security", value.clone());
    }
    if let Some(value) = &cfg.alt_svc {
        h.set_if_absent("Alt-Svc", value.clone());
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
        let secure = apply_edge_headers(&cfg(), Response::status(StatusCode::OK), true);
        assert_eq!(
            secure.headers().get("strict-transport-security"),
            Some("max-age=31536000")
        );
        let plain = apply_edge_headers(&cfg(), Response::status(StatusCode::OK), false);
        assert!(plain.headers().get("strict-transport-security").is_none());
    }

    #[test]
    fn hsts_absent_when_unset() {
        let c = SessionConfig::new(Arc::new(|_: &Request| Response::status(StatusCode::OK)));
        let r = apply_edge_headers(&c, Response::status(StatusCode::OK), true);
        assert!(r.headers().get("strict-transport-security").is_none());
    }
}
