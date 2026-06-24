//! HTTP protocol versions.

use std::fmt;

/// The HTTP version from the request line.
///
/// Only the HTTP/1.x family is parsed by this engine; `HTTP/2` and `HTTP/3`
/// use entirely different framing and are out of scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0 — connections close by default unless `Connection: keep-alive`.
    Http10,
    /// HTTP/1.1 — connections persist by default unless `Connection: close`.
    Http11,
}

impl Version {
    /// Parse the `HTTP/x.y` token from a request line.
    pub fn parse(token: &str) -> Option<Version> {
        match token {
            "HTTP/1.0" => Some(Version::Http10),
            "HTTP/1.1" => Some(Version::Http11),
            _ => None,
        }
    }

    /// The wire representation, e.g. `"HTTP/1.1"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
        }
    }

    /// Whether persistent connections are the default for this version.
    pub fn default_keep_alive(self) -> bool {
        matches!(self, Version::Http11)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
