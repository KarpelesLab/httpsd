//! HTTP/3 (RFC 9114), server side, over QUIC.
//!
//! [`H3Conn`] is the per-connection HTTP/3 engine; the QUIC transport itself is
//! provided by [`purecrypto::quic`]. The UDP event loop that binds a socket,
//! demultiplexes datagrams to connections, and drives timers lives in
//! [`crate::rt`] (`Server::run_h3`).

mod conn;

pub use conn::H3Conn;
