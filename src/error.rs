//! The crate-wide error type.

use std::fmt;

/// Errors produced by the HTTP engine, the runtimes, and configuration loading.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The peer sent a malformed request (bad request line, headers, or body
    /// framing). Carries a human-readable reason.
    BadRequest(&'static str),
    /// A request exceeded a configured limit (header bytes, body bytes, …).
    TooLarge(&'static str),
    /// An I/O error from a socket or the filesystem.
    Io(std::io::Error),
    /// A TLS-layer error (handshake failure, decrypt error, …). Only produced
    /// when the `tls` feature is enabled.
    Tls(String),
    /// A compression-layer error. Only produced when the `compress` feature is
    /// enabled.
    Compress(String),
    /// A configuration error (invalid TOML, missing file, bad value, …).
    Config(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadRequest(why) => write!(f, "bad request: {why}"),
            Error::TooLarge(what) => write!(f, "request too large: {what}"),
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Tls(e) => write!(f, "tls error: {e}"),
            Error::Compress(e) => write!(f, "compression error: {e}"),
            Error::Config(e) => write!(f, "config error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
