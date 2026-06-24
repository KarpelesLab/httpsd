//! Parsed HTTP requests.

use super::{Headers, Method, Version};

/// A fully-received HTTP request: the request line, headers, and a fully
/// buffered body.
///
/// The engine buffers the entire body before yielding a `Request`, so handlers
/// see a complete message. Streaming request bodies are out of scope for this
/// version.
#[derive(Debug, Clone)]
pub struct Request {
    method: Method,
    target: String,
    version: Version,
    headers: Headers,
    body: Vec<u8>,
}

impl Request {
    pub(crate) fn new(
        method: Method,
        target: String,
        version: Version,
        headers: Headers,
        body: Vec<u8>,
    ) -> Request {
        Request {
            method,
            target,
            version,
            headers,
            body,
        }
    }

    /// The request method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The raw request target (origin-form path, possibly with a query string),
    /// exactly as sent on the request line.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The path portion of the target, i.e. everything before the first `?`.
    pub fn path(&self) -> &str {
        match self.target.split_once('?') {
            Some((path, _)) => path,
            None => &self.target,
        }
    }

    /// The query string (without the leading `?`), if present.
    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, q)| q)
    }

    /// The HTTP version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The request headers.
    pub fn headers(&self) -> &Headers {
        &self.headers
    }

    /// The value of the `Host` header, if any.
    pub fn host(&self) -> Option<&str> {
        self.headers.get("host")
    }

    /// The buffered request body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The request body interpreted as UTF-8 (lossily).
    pub fn body_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// Consume the request and return the owned body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}
