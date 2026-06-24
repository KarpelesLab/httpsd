//! HTTP request methods.

use std::fmt;

/// An HTTP request method.
///
/// Common methods are represented as dedicated variants; anything else is kept
/// verbatim in [`Method::Other`] so the engine never rejects a request purely
/// because the method is unusual.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)] // the variant names are the canonical method tokens
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Connect,
    Options,
    Trace,
    Patch,
    /// Any other (still syntactically valid) method token.
    Other(String),
}

impl Method {
    /// Parse a method token from the request line.
    pub fn parse(token: &str) -> Method {
        match token {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "CONNECT" => Method::Connect,
            "OPTIONS" => Method::Options,
            "TRACE" => Method::Trace,
            "PATCH" => Method::Patch,
            other => Method::Other(other.to_owned()),
        }
    }

    /// The canonical uppercase token for this method.
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Connect => "CONNECT",
            Method::Options => "OPTIONS",
            Method::Trace => "TRACE",
            Method::Patch => "PATCH",
            Method::Other(s) => s,
        }
    }

    /// Whether a response to this method must omit its body (RFC 9110 §9.3.2).
    pub fn is_head(&self) -> bool {
        matches!(self, Method::Head)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
