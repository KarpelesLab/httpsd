//! HTTP response status codes.

/// An HTTP status code paired with its reason phrase.
///
/// Construct one of the common constants (e.g. [`StatusCode::OK`]) or build an
/// arbitrary code with [`StatusCode::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusCode {
    code: u16,
    reason: &'static str,
}

impl StatusCode {
    /// Build a status from a numeric code and reason phrase.
    pub const fn new(code: u16, reason: &'static str) -> StatusCode {
        StatusCode { code, reason }
    }

    /// The numeric code, e.g. `200`.
    pub const fn code(self) -> u16 {
        self.code
    }

    /// The reason phrase, e.g. `"OK"`.
    pub const fn reason(self) -> &'static str {
        self.reason
    }

    /// Whether the status forbids a message body (1xx, 204, 304).
    pub const fn is_bodyless(self) -> bool {
        matches!(self.code, 100..=199 | 204 | 304)
    }
}

/// Named constants for the status codes this crate uses. The names follow the
/// RFC 9110 registry; see [`StatusCode::reason`] for the phrase.
#[allow(missing_docs)]
impl StatusCode {
    pub const CONTINUE: StatusCode = StatusCode::new(100, "Continue");
    pub const OK: StatusCode = StatusCode::new(200, "OK");
    pub const CREATED: StatusCode = StatusCode::new(201, "Created");
    pub const ACCEPTED: StatusCode = StatusCode::new(202, "Accepted");
    pub const NO_CONTENT: StatusCode = StatusCode::new(204, "No Content");
    pub const PARTIAL_CONTENT: StatusCode = StatusCode::new(206, "Partial Content");
    pub const MOVED_PERMANENTLY: StatusCode = StatusCode::new(301, "Moved Permanently");
    pub const FOUND: StatusCode = StatusCode::new(302, "Found");
    pub const TEMPORARY_REDIRECT: StatusCode = StatusCode::new(307, "Temporary Redirect");
    pub const PERMANENT_REDIRECT: StatusCode = StatusCode::new(308, "Permanent Redirect");
    pub const NOT_MODIFIED: StatusCode = StatusCode::new(304, "Not Modified");
    pub const BAD_REQUEST: StatusCode = StatusCode::new(400, "Bad Request");
    pub const FORBIDDEN: StatusCode = StatusCode::new(403, "Forbidden");
    pub const NOT_FOUND: StatusCode = StatusCode::new(404, "Not Found");
    pub const METHOD_NOT_ALLOWED: StatusCode = StatusCode::new(405, "Method Not Allowed");
    pub const LENGTH_REQUIRED: StatusCode = StatusCode::new(411, "Length Required");
    pub const PAYLOAD_TOO_LARGE: StatusCode = StatusCode::new(413, "Content Too Large");
    pub const RANGE_NOT_SATISFIABLE: StatusCode = StatusCode::new(416, "Range Not Satisfiable");
    pub const URI_TOO_LONG: StatusCode = StatusCode::new(414, "URI Too Long");
    pub const REQUEST_HEADER_FIELDS_TOO_LARGE: StatusCode =
        StatusCode::new(431, "Request Header Fields Too Large");
    pub const INTERNAL_SERVER_ERROR: StatusCode = StatusCode::new(500, "Internal Server Error");
    pub const NOT_IMPLEMENTED: StatusCode = StatusCode::new(501, "Not Implemented");
    pub const SERVICE_UNAVAILABLE: StatusCode = StatusCode::new(503, "Service Unavailable");
    pub const HTTP_VERSION_NOT_SUPPORTED: StatusCode =
        StatusCode::new(505, "HTTP Version Not Supported");
}

impl From<u16> for StatusCode {
    /// Map a bare numeric code to a known reason phrase, falling back to a
    /// generic phrase for the class. The specific arms intentionally precede
    /// the class-range fallbacks.
    #[allow(clippy::match_overlapping_arm)]
    fn from(code: u16) -> StatusCode {
        let reason = match code {
            100 => "Continue",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            206 => "Partial Content",
            301 => "Moved Permanently",
            302 => "Found",
            304 => "Not Modified",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            413 => "Content Too Large",
            414 => "URI Too Long",
            416 => "Range Not Satisfiable",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            505 => "HTTP Version Not Supported",
            100..=199 => "Informational",
            200..=299 => "Success",
            300..=399 => "Redirection",
            400..=499 => "Client Error",
            _ => "Server Error",
        };
        StatusCode::new(code, reason)
    }
}
