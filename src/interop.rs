//! Interop with the [`http`](https://docs.rs/http) crate (feature `http`).
//!
//! httpsd deliberately defines its own `Request` / `Response` / `Method` /
//! `StatusCode` / `Headers` so the core stays dependency-free. When you want to
//! bridge to the wider ecosystem (tower/hyper-style middleware, libraries that
//! speak `http` types), enable the `http` feature and use the conversions here.
//!
//! Conversions follow the usual Rust convention: infallible directions are
//! [`From`], fallible ones are [`TryFrom`] with [`HttpConvertError`]. The
//! fallible direction is httpsd → `http` (a [`Method::Other`](crate::Method)
//! token, header name, or target string might not be valid `http` data); the
//! reverse is infallible (header values that are not UTF-8 are decoded lossily).
//!
//! ```
//! use httpsd::Response;
//!
//! // Build a response with the `http` crate; convert into an httpsd `Response`
//! // (and, with the `router` feature, return `http::Response` from a handler
//! // directly — it implements `IntoResponse`).
//! let h: http::Response<Vec<u8>> = http::Response::builder()
//!     .status(http::StatusCode::CREATED)
//!     .header("x-made-by", "http-crate")
//!     .body(b"hi".to_vec())
//!     .unwrap();
//! let resp: Response = h.into();
//! assert_eq!(resp.status_code().code(), 201);
//!
//! // The reverse, plus `Request`/`Method`/`StatusCode`/`Headers`, all convert
//! // too: `let out: http::Response<Vec<u8>> = resp.try_into()?;`
//! # Ok::<(), httpsd::interop::HttpConvertError>(())
//! ```

use http::header::{HeaderName, HeaderValue};

use crate::proto::{Body, Headers, Method, Request, Response, StatusCode, Version};

/// Error converting an httpsd value into the corresponding [`http`] crate type.
///
/// Only produced on the httpsd → `http` direction, where a method token, target
/// URI, or header field that httpsd accepts may not be valid per the stricter
/// `http` types.
#[derive(Debug)]
pub enum HttpConvertError {
    /// The method token is not a valid `http::Method`.
    Method(http::method::InvalidMethod),
    /// The status code is outside the valid range for `http::StatusCode`.
    Status(http::status::InvalidStatusCode),
    /// A header name is not a valid `http::HeaderName`.
    HeaderName(http::header::InvalidHeaderName),
    /// A header value is not a valid `http::HeaderValue`.
    HeaderValue(http::header::InvalidHeaderValue),
    /// The request target is not a valid `http::Uri`.
    Uri(http::uri::InvalidUri),
}

impl std::fmt::Display for HttpConvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpConvertError::Method(e) => write!(f, "invalid method: {e}"),
            HttpConvertError::Status(e) => write!(f, "invalid status code: {e}"),
            HttpConvertError::HeaderName(e) => write!(f, "invalid header name: {e}"),
            HttpConvertError::HeaderValue(e) => write!(f, "invalid header value: {e}"),
            HttpConvertError::Uri(e) => write!(f, "invalid uri: {e}"),
        }
    }
}

impl std::error::Error for HttpConvertError {}

impl From<http::method::InvalidMethod> for HttpConvertError {
    fn from(e: http::method::InvalidMethod) -> Self {
        HttpConvertError::Method(e)
    }
}
impl From<http::status::InvalidStatusCode> for HttpConvertError {
    fn from(e: http::status::InvalidStatusCode) -> Self {
        HttpConvertError::Status(e)
    }
}
impl From<http::header::InvalidHeaderName> for HttpConvertError {
    fn from(e: http::header::InvalidHeaderName) -> Self {
        HttpConvertError::HeaderName(e)
    }
}
impl From<http::header::InvalidHeaderValue> for HttpConvertError {
    fn from(e: http::header::InvalidHeaderValue) -> Self {
        HttpConvertError::HeaderValue(e)
    }
}
impl From<http::uri::InvalidUri> for HttpConvertError {
    fn from(e: http::uri::InvalidUri) -> Self {
        HttpConvertError::Uri(e)
    }
}

// --- Method ---------------------------------------------------------------

impl TryFrom<&Method> for http::Method {
    type Error = http::method::InvalidMethod;
    fn try_from(m: &Method) -> Result<Self, Self::Error> {
        http::Method::from_bytes(m.as_str().as_bytes())
    }
}

impl From<&http::Method> for Method {
    fn from(m: &http::Method) -> Self {
        Method::parse(m.as_str())
    }
}

// --- Version --------------------------------------------------------------

impl From<Version> for http::Version {
    fn from(v: Version) -> Self {
        match v {
            Version::Http10 => http::Version::HTTP_10,
            Version::Http11 => http::Version::HTTP_11,
            Version::Http2 => http::Version::HTTP_2,
            Version::Http3 => http::Version::HTTP_3,
        }
    }
}

impl From<http::Version> for Version {
    fn from(v: http::Version) -> Self {
        match v {
            http::Version::HTTP_2 => Version::Http2,
            http::Version::HTTP_3 => Version::Http3,
            http::Version::HTTP_10 => Version::Http10,
            // HTTP/0.9, HTTP/1.1, and any future variant fall back to 1.1.
            _ => Version::Http11,
        }
    }
}

// --- StatusCode -----------------------------------------------------------

impl TryFrom<StatusCode> for http::StatusCode {
    type Error = http::status::InvalidStatusCode;
    fn try_from(s: StatusCode) -> Result<Self, Self::Error> {
        http::StatusCode::from_u16(s.code())
    }
}

impl From<http::StatusCode> for StatusCode {
    fn from(s: http::StatusCode) -> Self {
        StatusCode::new(s.as_u16(), s.canonical_reason().unwrap_or(""))
    }
}

// --- Headers --------------------------------------------------------------

impl TryFrom<&Headers> for http::HeaderMap {
    type Error = HttpConvertError;
    fn try_from(headers: &Headers) -> Result<Self, Self::Error> {
        let mut map = http::HeaderMap::new();
        for (name, value) in headers.iter() {
            map.append(
                HeaderName::from_bytes(name.as_bytes())?,
                HeaderValue::from_str(value)?,
            );
        }
        Ok(map)
    }
}

impl From<&http::HeaderMap> for Headers {
    fn from(map: &http::HeaderMap) -> Self {
        let mut headers = Headers::new();
        for (name, value) in map.iter() {
            // Header values are usually ASCII; decode the rare non-UTF-8 ones
            // lossily rather than failing the whole conversion.
            headers.append(
                name.as_str(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            );
        }
        headers
    }
}

// --- Request --------------------------------------------------------------

impl TryFrom<&Request> for http::Request<Vec<u8>> {
    type Error = HttpConvertError;
    fn try_from(req: &Request) -> Result<Self, Self::Error> {
        let mut out = http::Request::new(req.body().to_vec());
        *out.method_mut() = http::Method::try_from(req.method())?;
        *out.uri_mut() = req.target().parse::<http::Uri>()?;
        *out.version_mut() = req.version().into();
        *out.headers_mut() = http::HeaderMap::try_from(req.headers())?;
        Ok(out)
    }
}

impl From<http::Request<Vec<u8>>> for Request {
    fn from(req: http::Request<Vec<u8>>) -> Self {
        let (parts, body) = req.into_parts();
        let target = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_owned())
            .unwrap_or_else(|| "/".to_owned());
        Request::new(
            Method::from(&parts.method),
            target,
            Version::from(parts.version),
            Headers::from(&parts.headers),
            body,
        )
    }
}

// --- Response -------------------------------------------------------------

impl TryFrom<Response> for http::Response<Vec<u8>> {
    type Error = HttpConvertError;
    fn try_from(resp: Response) -> Result<Self, Self::Error> {
        let (status, headers, body) = resp.into_parts();
        // Materialize the body (a file body is read into memory; `http` carries
        // an owned `Vec<u8>`).
        let mut out = http::Response::new(body.into_bytes());
        *out.status_mut() = http::StatusCode::try_from(status)?;
        *out.headers_mut() = http::HeaderMap::try_from(&headers)?;
        Ok(out)
    }
}

impl From<http::Response<Vec<u8>>> for Response {
    fn from(resp: http::Response<Vec<u8>>) -> Self {
        let (parts, body) = resp.into_parts();
        Response::from_parts(
            StatusCode::from(parts.status),
            Headers::from(&parts.headers),
            Body::from(body),
        )
    }
}

/// `http::Response` can be returned directly from a [`Router`](crate::Router)
/// handler.
#[cfg(feature = "router")]
impl crate::router::IntoResponse for http::Response<Vec<u8>> {
    fn into_response(self) -> Response {
        self.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_roundtrip() {
        let h: http::Method = (&Method::Post).try_into().unwrap();
        assert_eq!(h, http::Method::POST);
        assert_eq!(Method::from(&http::Method::DELETE), Method::Delete);
    }

    #[test]
    fn status_roundtrip() {
        let h: http::StatusCode = StatusCode::NOT_FOUND.try_into().unwrap();
        assert_eq!(h, http::StatusCode::NOT_FOUND);
        assert_eq!(StatusCode::from(http::StatusCode::CREATED).code(), 201);
    }

    #[test]
    fn response_from_http_keeps_status_headers_body() {
        let h = http::Response::builder()
            .status(http::StatusCode::ACCEPTED)
            .header("x-test", "1")
            .header("x-test", "2")
            .body(b"body".to_vec())
            .unwrap();
        let resp: Response = h.into();
        assert_eq!(resp.status_code().code(), 202);
        assert_eq!(resp.body_ref().as_bytes(), b"body");
        let vals: Vec<_> = resp.headers().get_all("x-test").collect();
        assert_eq!(vals, ["1", "2"]);
    }

    #[test]
    fn request_to_http_carries_target_and_headers() {
        let mut headers = Headers::new();
        headers.append("Host", "example.com");
        let req = Request::new(
            Method::Get,
            "/path?q=1".to_owned(),
            Version::Http11,
            headers,
            Vec::new(),
        );
        let out: http::Request<Vec<u8>> = (&req).try_into().unwrap();
        assert_eq!(out.method(), http::Method::GET);
        assert_eq!(out.uri().path(), "/path");
        assert_eq!(out.uri().query(), Some("q=1"));
        assert_eq!(out.headers().get("host").unwrap(), "example.com");
    }

    #[test]
    fn response_to_http_and_back() {
        let resp = Response::text("hello").with_status(StatusCode::OK);
        let h: http::Response<Vec<u8>> = resp.try_into().unwrap();
        assert_eq!(h.status(), http::StatusCode::OK);
        let back: Response = h.into();
        assert_eq!(back.body_ref().as_bytes(), b"hello");
    }
}
