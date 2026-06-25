//! The sans-I/O HTTP/1.x connection engine.
//!
//! [`H1Conn`] owns no socket. You [`feed`](H1Conn::feed) it the plaintext bytes
//! that arrived on the connection, [`poll_request`](H1Conn::poll_request) until
//! it yields a complete [`Request`], hand it back a [`Response`] with
//! [`respond`](H1Conn::respond), and drain the serialized reply with
//! [`take_out`](H1Conn::take_out). A runtime driver supplies the actual I/O (and,
//! for HTTPS, a TLS layer sits between the socket and this engine).

use std::time::{SystemTime, UNIX_EPOCH};

use super::{Headers, Method, Request, Response, StatusCode, Version};
use crate::error::{Error, Result};

/// Tunable limits applied while parsing requests, to bound memory use and
/// reject abusive peers.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum size of the request line + header block, in bytes.
    pub max_header_bytes: usize,
    /// Maximum size of a (buffered) request body, in bytes.
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Per-request facts the engine must remember between [`H1Conn::poll_request`]
/// and [`H1Conn::respond`].
#[derive(Debug, Clone, Copy)]
struct Pending {
    version: Version,
    keep_alive: bool,
    is_head: bool,
}

/// A sans-I/O HTTP/1.x server connection.
#[derive(Debug)]
pub struct H1Conn {
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    limits: Limits,
    /// The request currently awaiting a response, if any. While set,
    /// `poll_request` yields nothing (one in-flight request at a time).
    pending: Option<Pending>,
    /// Set once a response with `Connection: close` (or a fatal error) has been
    /// serialized; the driver should close after draining `outbuf`.
    closed: bool,
    /// Whether a `100 Continue` interim response has already been emitted for
    /// the request currently being received.
    interim_sent: bool,
    /// Optional `Server` header value advertised on responses.
    server_name: Option<String>,
}

impl Default for H1Conn {
    fn default() -> H1Conn {
        H1Conn::new(Limits::default())
    }
}

impl H1Conn {
    /// Create a new connection engine with the given limits.
    pub fn new(limits: Limits) -> H1Conn {
        H1Conn {
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            limits,
            pending: None,
            closed: false,
            interim_sent: false,
            server_name: Some(concat!("httpsd/", env!("CARGO_PKG_VERSION")).to_owned()),
        }
    }

    /// Set the `Server` header value (or `None` to omit it).
    pub fn set_server_name(&mut self, name: Option<String>) {
        self.server_name = name;
    }

    /// Push freshly received plaintext bytes into the engine.
    pub fn feed(&mut self, data: &[u8]) {
        self.inbuf.extend_from_slice(data);
    }

    /// Drain and return all serialized response bytes queued so far.
    ///
    /// The caller is expected to write the returned bytes to the transport in
    /// full. Returns an empty vec when there is nothing pending.
    pub fn take_out(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbuf)
    }

    /// Whether there are serialized bytes waiting to be written.
    pub fn has_output(&self) -> bool {
        !self.outbuf.is_empty()
    }

    /// Whether the connection should be closed once `outbuf` has been written.
    pub fn wants_close(&self) -> bool {
        self.closed
    }

    /// Whether a request has been delivered and is awaiting [`respond`](Self::respond).
    pub fn awaiting_response(&self) -> bool {
        self.pending.is_some()
    }

    /// Try to parse the next complete request from the buffered input.
    ///
    /// Returns `Ok(Some(req))` when a full request (headers + body) is
    /// available, `Ok(None)` when more bytes are needed, and `Err(..)` on a
    /// protocol violation — in which case an error response has already been
    /// queued via [`take_out`](Self::take_out) and the connection is marked for
    /// close.
    pub fn poll_request(&mut self) -> Result<Option<Request>> {
        if self.closed || self.pending.is_some() {
            return Ok(None);
        }

        // Locate the end of the header block.
        let Some(head_end) = find_subslice(&self.inbuf, b"\r\n\r\n") else {
            if self.inbuf.len() > self.limits.max_header_bytes {
                return Err(self.fail(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "headers"));
            }
            return Ok(None);
        };
        let header_block_len = head_end; // bytes before the terminator
        if header_block_len > self.limits.max_header_bytes {
            return Err(self.fail(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "headers"));
        }
        let body_start = head_end + 4;

        // Parse request line + headers from the header block.
        let head = &self.inbuf[..header_block_len];
        let (method, target, version, headers) = match parse_head(head) {
            Ok(parts) => parts,
            Err(e) => {
                // Map parse errors to the right status, then fail the connection.
                let status = match &e {
                    Error::BadRequest(_) => StatusCode::BAD_REQUEST,
                    _ => StatusCode::BAD_REQUEST,
                };
                return Err(self.fail(status, "request line/headers"));
            }
        };

        if version.is_none() {
            return Err(self.fail(StatusCode::HTTP_VERSION_NOT_SUPPORTED, "version"));
        }
        let version = version.unwrap();

        // Determine body framing.
        let framing = match body_framing(&headers) {
            Ok(f) => f,
            Err(()) => return Err(self.fail(StatusCode::BAD_REQUEST, "body framing")),
        };

        // Resolve the body (may need more bytes).
        let body: Vec<u8>;
        let consumed_total: usize;
        match framing {
            BodyFraming::None => {
                body = Vec::new();
                consumed_total = body_start;
            }
            BodyFraming::Length(len) => {
                if len > self.limits.max_body_bytes {
                    return Err(self.fail(StatusCode::PAYLOAD_TOO_LARGE, "body"));
                }
                if self.inbuf.len() < body_start + len {
                    self.maybe_send_continue(&headers);
                    return Ok(None);
                }
                body = self.inbuf[body_start..body_start + len].to_vec();
                consumed_total = body_start + len;
            }
            BodyFraming::Chunked => {
                match decode_chunked(&self.inbuf[body_start..], self.limits.max_body_bytes) {
                    Ok(Some((decoded, used))) => {
                        body = decoded;
                        consumed_total = body_start + used;
                    }
                    Ok(None) => {
                        self.maybe_send_continue(&headers);
                        return Ok(None);
                    }
                    Err(status) => return Err(self.fail(status, "chunked body")),
                }
            }
        }

        // Commit: drop the consumed bytes and remember per-request state.
        self.inbuf.drain(..consumed_total);
        self.interim_sent = false;

        let keep_alive = negotiate_keep_alive(version, &headers);
        let is_head = method.is_head();
        self.pending = Some(Pending {
            version,
            keep_alive,
            is_head,
        });

        Ok(Some(Request::new(method, target, version, headers, body)))
    }

    /// Serialize `resp` for the request most recently returned by
    /// [`poll_request`](Self::poll_request).
    ///
    /// Panics if there is no request awaiting a response.
    pub fn respond(&mut self, resp: Response) {
        let meta = self
            .pending
            .take()
            .expect("respond() called with no request in flight");
        self.serialize(meta, resp);
    }

    // ---- internals ----

    /// Queue a self-contained error response and mark the connection closed.
    fn fail(&mut self, status: StatusCode, what: &'static str) -> Error {
        let meta = Pending {
            version: Version::Http11,
            keep_alive: false,
            is_head: false,
        };
        let resp = Response::status(status);
        self.pending = None;
        self.serialize(meta, resp);
        self.closed = true;
        match status.code() {
            413 | 431 => Error::TooLarge(what),
            _ => Error::BadRequest(what),
        }
    }

    fn maybe_send_continue(&mut self, headers: &Headers) {
        if !self.interim_sent && headers.contains_token("expect", "100-continue") {
            self.outbuf
                .extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
            self.interim_sent = true;
        }
    }

    fn serialize(&mut self, meta: Pending, resp: Response) {
        let (status, mut headers, body) = resp.into_parts();
        let bodyless = status.is_bodyless();
        let omit_body = bodyless || meta.is_head;

        // Framing headers.
        if !bodyless {
            // Authoritative Content-Length (handlers should not set their own).
            headers.set("Content-Length", body.len().to_string());
        } else {
            headers.remove("Content-Length");
        }

        let keep_alive = meta.keep_alive && !self.closed;
        headers.set(
            "Connection",
            if keep_alive { "keep-alive" } else { "close" },
        );

        if let Some(server) = &self.server_name {
            headers.set_if_absent("Server", server.clone());
        }
        headers.set_if_absent("Date", http_date(now_secs()));

        // Status line.
        let line = format!(
            "{} {} {}\r\n",
            meta.version.as_str(),
            status.code(),
            status.reason()
        );
        self.outbuf.extend_from_slice(line.as_bytes());

        for (name, value) in headers.iter() {
            self.outbuf.extend_from_slice(name.as_bytes());
            self.outbuf.extend_from_slice(b": ");
            self.outbuf.extend_from_slice(value.as_bytes());
            self.outbuf.extend_from_slice(b"\r\n");
        }
        self.outbuf.extend_from_slice(b"\r\n");

        if !omit_body {
            self.outbuf.extend_from_slice(&body);
        }

        if !keep_alive {
            self.closed = true;
        }
    }
}

/// How a request body is delimited.
enum BodyFraming {
    None,
    Length(usize),
    Chunked,
}

/// Decide body framing from headers, rejecting the smuggling-prone combination
/// of both `Transfer-Encoding` and `Content-Length`.
fn body_framing(headers: &Headers) -> std::result::Result<BodyFraming, ()> {
    let chunked = headers.contains_token("transfer-encoding", "chunked");
    let has_te = headers.contains("transfer-encoding");
    let has_cl = headers.contains("content-length");

    if has_te && has_cl {
        return Err(());
    }
    if chunked {
        return Ok(BodyFraming::Chunked);
    }
    if has_te {
        // A Transfer-Encoding we don't understand (and not chunked) is unsupported.
        return Err(());
    }
    // Multiple Content-Length values must agree.
    let mut len: Option<usize> = None;
    for v in headers.get_all("content-length") {
        let parsed: usize = v.trim().parse().map_err(|_| ())?;
        match len {
            Some(prev) if prev != parsed => return Err(()),
            _ => len = Some(parsed),
        }
    }
    match len {
        Some(0) | None => Ok(BodyFraming::None),
        Some(n) => Ok(BodyFraming::Length(n)),
    }
}

/// Negotiate connection persistence per RFC 9112 §9.3.
fn negotiate_keep_alive(version: Version, headers: &Headers) -> bool {
    if headers.contains_token("connection", "close") {
        return false;
    }
    if headers.contains_token("connection", "keep-alive") {
        return true;
    }
    version.default_keep_alive()
}

/// Parse the request line and header fields from the header block (the bytes
/// before the terminating CRLFCRLF).
fn parse_head(head: &[u8]) -> Result<(Method, String, Option<Version>, Headers)> {
    let text = std::str::from_utf8(head).map_err(|_| Error::BadRequest("non-UTF-8 header"))?;
    let mut lines = text.split("\r\n");

    let request_line = lines.next().ok_or(Error::BadRequest("empty request"))?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or(Error::BadRequest("no method"))?;
    let target = parts.next().ok_or(Error::BadRequest("no target"))?;
    let version_tok = parts.next().ok_or(Error::BadRequest("no version"))?;
    if parts.next().is_some() {
        return Err(Error::BadRequest("trailing request-line tokens"));
    }
    if method.is_empty() || target.is_empty() {
        return Err(Error::BadRequest("empty request-line token"));
    }

    let method = Method::parse(method);
    let version = Version::parse(version_tok);

    let mut headers = Headers::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        // Reject obsolete line folding (leading whitespace continuation).
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(Error::BadRequest("obsolete header folding"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(Error::BadRequest("header without colon"))?;
        if name.is_empty() || name.contains(' ') {
            return Err(Error::BadRequest("invalid header name"));
        }
        headers.append(name.trim(), value.trim());
    }

    Ok((method, target.to_owned(), version, headers))
}

/// Decode a complete chunked body from `data`.
///
/// Returns `Ok(Some((body, consumed)))` once the terminating zero-length chunk
/// (and trailing CRLF) have arrived, `Ok(None)` if more bytes are needed, or
/// `Err(status)` on a malformed or oversized body.
fn decode_chunked(
    data: &[u8],
    max_body: usize,
) -> std::result::Result<Option<(Vec<u8>, usize)>, StatusCode> {
    let mut pos = 0usize;
    let mut out = Vec::new();
    loop {
        // Chunk size line.
        let Some(eol) = find_subslice(&data[pos..], b"\r\n") else {
            return Ok(None);
        };
        let size_line = &data[pos..pos + eol];
        // Strip any chunk extensions after ';'.
        let hex = match size_line.iter().position(|&b| b == b';') {
            Some(i) => &size_line[..i],
            None => size_line,
        };
        let hex = std::str::from_utf8(hex).map_err(|_| StatusCode::BAD_REQUEST)?;
        let size = usize::from_str_radix(hex.trim(), 16).map_err(|_| StatusCode::BAD_REQUEST)?;
        let after_size = pos + eol + 2;

        if size == 0 {
            // Last chunk; consume optional trailers up to the final CRLF.
            let Some(term) = find_subslice(&data[after_size..], b"\r\n") else {
                return Ok(None);
            };
            let consumed = after_size + term + 2;
            return Ok(Some((out, consumed)));
        }

        if out.len() + size > max_body {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        // Need the chunk data plus its trailing CRLF.
        if data.len() < after_size + size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&data[after_size..after_size + size]);
        if &data[after_size + size..after_size + size + 2] != b"\r\n" {
            return Err(StatusCode::BAD_REQUEST);
        }
        pos = after_size + size + 2;
    }
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Current Unix time in whole seconds (0 if the clock is before the epoch).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a Unix timestamp as an RFC 9110 IMF-fixdate, e.g.
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
pub(crate) fn http_date(secs: u64) -> String {
    const WDAY: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    if month <= 2 {
        year += 1;
    }

    let wday = ((days % 7 + 7) % 7 + 4) % 7; // 1970-01-01 was a Thursday

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WDAY[wday as usize],
        day,
        MON[(month - 1) as usize],
        year,
        h,
        mi,
        s,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive(conn: &mut H1Conn, input: &[u8]) -> Option<Request> {
        conn.feed(input);
        conn.poll_request().unwrap()
    }

    #[test]
    fn parses_simple_get() {
        let mut c = H1Conn::default();
        let req = drive(&mut c, b"GET /hello?x=1 HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        assert_eq!(req.method(), &Method::Get);
        assert_eq!(req.path(), "/hello");
        assert_eq!(req.query(), Some("x=1"));
        assert_eq!(req.host(), Some("a"));
        assert!(req.body().is_empty());
    }

    #[test]
    fn waits_for_full_body() {
        let mut c = H1Conn::default();
        c.feed(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab");
        assert!(c.poll_request().unwrap().is_none());
        c.feed(b"cde");
        let req = c.poll_request().unwrap().unwrap();
        assert_eq!(req.body(), b"abcde");
    }

    #[test]
    fn decodes_chunked() {
        let mut c = H1Conn::default();
        let req = drive(
            &mut c,
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(req.body(), b"hello");
    }

    #[test]
    fn keep_alive_default_by_version() {
        let mut c = H1Conn::default();
        let req = drive(&mut c, b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert!(negotiate_keep_alive(req.version(), req.headers()));
        let mut c = H1Conn::default();
        let req = drive(&mut c, b"GET / HTTP/1.0\r\n\r\n").unwrap();
        assert!(!negotiate_keep_alive(req.version(), req.headers()));
    }

    #[test]
    fn serializes_response_with_framing() {
        let mut c = H1Conn::default();
        let _ = drive(&mut c, b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
        c.respond(Response::text("hi"));
        let out = String::from_utf8(c.take_out()).unwrap();
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(out.contains("Content-Length: 2\r\n"));
        assert!(out.contains("Connection: close\r\n"));
        assert!(out.ends_with("\r\n\r\nhi"));
        assert!(c.wants_close());
    }

    #[test]
    fn head_omits_body_keeps_length() {
        let mut c = H1Conn::default();
        let _ = drive(&mut c, b"HEAD / HTTP/1.1\r\n\r\n").unwrap();
        c.respond(Response::text("hello"));
        let out = String::from_utf8(c.take_out()).unwrap();
        assert!(out.contains("Content-Length: 5\r\n"));
        assert!(out.ends_with("\r\n\r\n")); // no body
    }

    #[test]
    fn rejects_te_and_cl_together() {
        let mut c = H1Conn::default();
        c.feed(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert!(c.poll_request().is_err());
        assert!(c.wants_close());
        let out = String::from_utf8(c.take_out()).unwrap();
        assert!(out.starts_with("HTTP/1.1 400"));
    }

    #[test]
    fn http_date_known_value() {
        // 784111777 = Sun, 06 Nov 1994 08:49:37 GMT
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    }
}
