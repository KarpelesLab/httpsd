//! HTTP responses produced by handlers.

use super::{Headers, StatusCode};

/// The body of a response.
///
/// Bodies are buffered: a handler hands the engine the complete bytes (or
/// declares an empty body). This keeps the sans-I/O core simple and lets the
/// compression layer choose an encoding with the full length in hand.
#[derive(Debug, Clone, Default)]
pub struct Body {
    bytes: Vec<u8>,
}

impl Body {
    /// An empty body.
    pub fn empty() -> Body {
        Body { bytes: Vec::new() }
    }

    /// The body bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The body length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the body is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Body {
        Body { bytes }
    }
}

impl From<&[u8]> for Body {
    fn from(bytes: &[u8]) -> Body {
        Body {
            bytes: bytes.to_vec(),
        }
    }
}

impl From<String> for Body {
    fn from(s: String) -> Body {
        Body {
            bytes: s.into_bytes(),
        }
    }
}

impl From<&str> for Body {
    fn from(s: &str) -> Body {
        Body {
            bytes: s.as_bytes().to_vec(),
        }
    }
}

/// A response to be serialized onto the connection.
///
/// Build one with [`Response::new`] or the status helpers, then chain
/// [`Response::header`] / [`Response::body`]. The engine fills in framing
/// headers (`Content-Length`, `Connection`, `Date`) at serialization time, so
/// handlers only set what they care about.
#[derive(Debug, Clone)]
pub struct Response {
    status: StatusCode,
    headers: Headers,
    body: Body,
}

impl Response {
    /// A response with the given status, no headers, and an empty body.
    pub fn new(status: StatusCode) -> Response {
        Response {
            status,
            headers: Headers::new(),
            body: Body::empty(),
        }
    }

    /// `200 OK` with the given body and a `Content-Type` of `text/plain`.
    pub fn text(body: impl Into<String>) -> Response {
        Response::new(StatusCode::OK)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(body.into())
    }

    /// `200 OK` with the given HTML body.
    pub fn html(body: impl Into<String>) -> Response {
        Response::new(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(body.into())
    }

    /// A bodyless response carrying just a status, with a short `text/plain`
    /// explanation as the body (useful for error pages).
    pub fn status(status: StatusCode) -> Response {
        let page = format!("{} {}\n", status.code(), status.reason());
        if status.is_bodyless() {
            Response::new(status)
        } else {
            Response::new(status)
                .header("Content-Type", "text/plain; charset=utf-8")
                .body(page)
        }
    }

    /// A redirect to `location` with the given 3xx status.
    pub fn redirect(status: StatusCode, location: impl Into<String>) -> Response {
        Response::new(status).header("Location", location.into())
    }

    /// Add a header field (builder style), keeping any existing same-named field.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Response {
        self.headers.append(name, value);
        self
    }

    /// Set the body (builder style).
    pub fn body(mut self, body: impl Into<Body>) -> Response {
        self.body = body.into();
        self
    }

    /// Override the status code (builder style), keeping headers and body.
    pub fn with_status(mut self, status: StatusCode) -> Response {
        self.status = status;
        self
    }

    /// The status code.
    pub fn status_code(&self) -> StatusCode {
        self.status
    }

    /// Mutable access to the response headers.
    pub fn headers_mut(&mut self) -> &mut Headers {
        &mut self.headers
    }

    /// The response headers.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// The response body.
    pub fn body_ref(&self) -> &Body {
        &self.body
    }

    pub(crate) fn into_parts(self) -> (StatusCode, Headers, Vec<u8>) {
        (self.status, self.headers, self.body.into_bytes())
    }

    // Used by the compression layer to rebuild a response after re-encoding.
    #[cfg_attr(not(feature = "compress"), allow(dead_code))]
    pub(crate) fn from_parts(status: StatusCode, headers: Headers, body: Vec<u8>) -> Response {
        Response {
            status,
            headers,
            body: Body::from(body),
        }
    }
}
