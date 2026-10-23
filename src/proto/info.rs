//! Per-connection facts exposed to handlers.

use std::net::SocketAddr;

/// Facts about the connection a [`Request`](super::Request) arrived on: the
/// peer and local socket addresses and, on a secure connection, the
/// negotiated TLS parameters.
///
/// The bundled runtimes fill this in for every request; read it with
/// [`Request::conn`](super::Request::conn) (or the shortcuts
/// [`Request::peer_addr`](super::Request::peer_addr),
/// [`Request::local_addr`](super::Request::local_addr) and
/// [`Request::is_secure`](super::Request::is_secure)). A custom driver that
/// owns the socket passes the addresses to
/// [`Session::set_addrs`](crate::Session::set_addrs); the TLS fields are
/// filled in by the session itself.
///
/// Every field is optional: a request built by hand (or by a driver that
/// doesn't know an address) simply reports `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnInfo {
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    secure: bool,
    tls_version: Option<&'static str>,
    cipher_suite: Option<&'static str>,
    alpn: Option<Vec<u8>>,
    server_name: Option<String>,
}

impl ConnInfo {
    /// An empty record: no addresses, not secure.
    pub const fn new() -> ConnInfo {
        ConnInfo {
            peer_addr: None,
            local_addr: None,
            secure: false,
            tls_version: None,
            cipher_suite: None,
            alpn: None,
            server_name: None,
        }
    }

    /// Set the peer (client) address.
    pub fn with_peer_addr(mut self, addr: Option<SocketAddr>) -> ConnInfo {
        self.peer_addr = addr;
        self
    }

    /// Set the local (server) address the connection was accepted on.
    pub fn with_local_addr(mut self, addr: Option<SocketAddr>) -> ConnInfo {
        self.local_addr = addr;
        self
    }

    /// Mark the connection as secure (TLS or QUIC).
    pub fn with_secure(mut self, secure: bool) -> ConnInfo {
        self.secure = secure;
        self
    }

    /// Set the negotiated TLS version name, e.g. `"TLSv1.3"`.
    pub fn with_tls_version(mut self, version: Option<&'static str>) -> ConnInfo {
        self.tls_version = version;
        self
    }

    /// Set the negotiated cipher-suite name, e.g. `"TLS_AES_128_GCM_SHA256"`.
    pub fn with_cipher_suite(mut self, suite: Option<&'static str>) -> ConnInfo {
        self.cipher_suite = suite;
        self
    }

    /// Set the ALPN protocol, e.g. `b"h2"`.
    pub fn with_alpn(mut self, alpn: Option<Vec<u8>>) -> ConnInfo {
        self.alpn = alpn;
        self
    }

    /// Set the TLS SNI host name the client asked for.
    pub fn with_server_name(mut self, name: Option<String>) -> ConnInfo {
        self.server_name = name;
        self
    }

    /// The peer (client) address, e.g. for a CGI-style `REMOTE_ADDR` /
    /// `REMOTE_PORT`.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// The local address the connection was accepted on (`SERVER_ADDR` /
    /// `SERVER_PORT`). For HTTP/3 this is the bound UDP address, which may be
    /// a wildcard such as `0.0.0.0`.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Whether the connection is encrypted (HTTPS, including HTTP/2 and
    /// HTTP/3).
    pub fn is_secure(&self) -> bool {
        self.secure
    }

    /// The negotiated TLS version, e.g. `"TLSv1.2"` or `"TLSv1.3"`.
    pub fn tls_version(&self) -> Option<&'static str> {
        self.tls_version
    }

    /// The negotiated cipher suite's IANA name.
    pub fn cipher_suite(&self) -> Option<&'static str> {
        self.cipher_suite
    }

    /// The ALPN protocol negotiated during the handshake (`b"h2"`,
    /// `b"http/1.1"`, `b"h3"`), if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// The SNI host name the client sent in its TLS ClientHello, if any.
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }
}
