//! HTTP/2 (RFC 9113), server side, as a sans-I/O engine.
//!
//! [`H2Conn`] mirrors [`H1Conn`](crate::proto::H1Conn) but multiplexes many
//! requests over one connection. It is selected automatically when a TLS client
//! negotiates the `h2` protocol via ALPN; see [`crate::session::Session`].

mod conn;
mod frame;

pub use conn::H2Conn;
