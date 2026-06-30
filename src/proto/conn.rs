//! The sans-I/O HTTP/1.x connection engine.
//!
//! [`H1Conn`] owns no socket. You [`feed`](H1Conn::feed) it the plaintext bytes
//! that arrived on the connection, [`poll_request`](H1Conn::poll_request) until
//! it yields a complete [`Request`], hand it back a [`Response`] with
//! [`respond`](H1Conn::respond), and drain the serialized reply with
//! [`take_out`](H1Conn::take_out). A runtime driver supplies the actual I/O (and,
//! for HTTPS, a TLS layer sits between the socket and this engine).

use std::fs::File;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::response::STREAM_CHUNK;
use super::{Body, Headers, Method, Request, Response, StatusCode, Version};
use crate::error::{Error, Result};
use crate::proto::read_at_exact;

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

/// A response body being streamed from a file across multiple drains.
#[derive(Debug)]
struct FileBody {
    file: Arc<File>,
    /// Absolute offset of the next byte to read.
    offset: u64,
    /// Bytes still to send.
    remaining: u64,
}

/// A sans-I/O HTTP/1.x server connection.
#[derive(Debug)]
pub struct H1Conn {
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    /// A file body still being streamed out. While set, [`take_out`](H1Conn::take_out)
    /// keeps yielding the next `STREAM_CHUNK`-sized slice until EOF.
    body_stream: Option<FileBody>,
    limits: Limits,
    /// The request currently awaiting a response, if any. While set,
    /// `poll_request` yields nothing (one in-flight request at a time).
    pending: Option<Pending>,
    /// How far into `inbuf` we have already scanned for the header-terminating
    /// `\r\n\r\n`. Lets a request fed one byte at a time resume the scan instead
    /// of re-scanning the whole buffer every poll (otherwise O(n²)). Indexes
    /// into `inbuf`, so it MUST be reset to 0 whenever consumed bytes are
    /// drained from `inbuf`.
    head_scanned: usize,
    /// In-progress chunked-body decode state, persisted across polls so a slowly
    /// arriving body is decoded incrementally rather than from offset 0 each
    /// time (otherwise O(n²)). Present only while a chunked body is mid-receive.
    chunk: Option<ChunkDecoder>,
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
            body_stream: None,
            limits,
            pending: None,
            head_scanned: 0,
            chunk: None,
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

    /// Drain and return the next batch of serialized response bytes.
    ///
    /// The caller is expected to write the returned bytes to the transport in
    /// full, then keep calling while [`has_output`](Self::has_output) is true so
    /// a file body is streamed to completion. Returns queued buffer bytes first;
    /// once those are drained it reads and returns the next `STREAM_CHUNK` of
    /// any in-progress file body. Returns an empty vec when there is nothing
    /// pending. A mid-stream read error (or a file that shrank) drops the stream
    /// and marks the connection for close rather than panicking.
    pub fn take_out(&mut self) -> Vec<u8> {
        if !self.outbuf.is_empty() {
            return std::mem::take(&mut self.outbuf);
        }
        let Some(fb) = self.body_stream.as_mut() else {
            return Vec::new();
        };
        let want = (fb.remaining as usize).min(STREAM_CHUNK);
        let mut buf = vec![0u8; want];
        match read_at_exact(&fb.file, fb.offset, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                fb.offset += n as u64;
                fb.remaining -= n as u64;
                if n < want {
                    // The file came up short of the promised Content-Length: the
                    // response is now corrupt, so close the connection.
                    self.body_stream = None;
                    self.closed = true;
                } else if fb.remaining == 0 {
                    self.body_stream = None;
                }
                buf
            }
            Err(_) => {
                self.body_stream = None;
                self.closed = true;
                Vec::new()
            }
        }
    }

    /// Whether there is output still to be written — queued bytes or an
    /// in-progress file body that has not reached EOF.
    pub fn has_output(&self) -> bool {
        !self.outbuf.is_empty() || self.body_stream.is_some()
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

        // Locate the end of the header block, resuming the scan where the
        // previous poll left off so a request fed one byte at a time is not
        // re-scanned from the start (which would be O(n²)). Back up by 3 bytes
        // so a `\r\n\r\n` straddling the previous boundary is still found.
        let search_from = self.head_scanned.saturating_sub(3);
        let head_end = match find_subslice(&self.inbuf[search_from..], b"\r\n\r\n") {
            Some(rel) => {
                let end = search_from + rel;
                // Resume future scans right at the terminator: while we wait for
                // the body, re-finding it then costs O(1) instead of re-scanning
                // the (possibly large) buffered body for the header terminator.
                self.head_scanned = end + 3;
                end
            }
            None => {
                self.head_scanned = self.inbuf.len();
                if self.inbuf.len() > self.limits.max_header_bytes {
                    return Err(self.fail(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, "headers"));
                }
                return Ok(None);
            }
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
                // Resume the incremental decoder where the previous poll stopped
                // (or start a fresh one). `body_start` is stable for the lifetime
                // of this request — `inbuf` is not drained until it completes —
                // so the decoder's offsets remain valid across polls.
                let mut dec = self.chunk.take().unwrap_or_default();
                match dec.advance(&self.inbuf[body_start..], self.limits.max_body_bytes) {
                    Ok(Some(used)) => {
                        body = std::mem::take(&mut dec.out);
                        consumed_total = body_start + used;
                    }
                    Ok(None) => {
                        self.chunk = Some(dec);
                        self.maybe_send_continue(&headers);
                        return Ok(None);
                    }
                    Err(status) => return Err(self.fail(status, "chunked body")),
                }
            }
        }

        // Commit: drop the consumed bytes and remember per-request state. The
        // header scan cursor indexes into `inbuf`, so reset it now that those
        // bytes are gone; the chunked decoder (if any) was consumed above.
        self.inbuf.drain(..consumed_total);
        self.head_scanned = 0;
        self.chunk = None;
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
        self.head_scanned = 0;
        self.chunk = None;
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

        // Strip hop-by-hop / framing headers a handler may have supplied so the
        // engine's own framing (Content-Length / Connection) stays authoritative
        // and no rogue Transfer-Encoding can desync the connection.
        for h in HOP_BY_HOP_HEADERS {
            headers.remove(h);
        }

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
            // Never emit a header whose name is not a valid token or whose value
            // carries CR/LF/NUL: that would allow response splitting / header
            // injection from handler-controlled data.
            if !is_token(name)
                || value
                    .bytes()
                    .any(|b| b == b'\r' || b == b'\n' || b == b'\0')
            {
                continue;
            }
            self.outbuf.extend_from_slice(name.as_bytes());
            self.outbuf.extend_from_slice(b": ");
            self.outbuf.extend_from_slice(value.as_bytes());
            self.outbuf.extend_from_slice(b"\r\n");
        }
        self.outbuf.extend_from_slice(b"\r\n");

        if !omit_body {
            match body {
                Body::Bytes(bytes) => self.outbuf.extend_from_slice(&bytes),
                // Stream a file body across subsequent `take_out` calls rather
                // than buffering it. HEAD/bodyless responses fall in the
                // `omit_body` arm above, so no read happens for them.
                Body::File { file, offset, len } if len > 0 => {
                    self.body_stream = Some(FileBody {
                        file,
                        offset,
                        remaining: len,
                    });
                }
                Body::File { .. } => {}
            }
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
        // Require a non-empty, all-ASCII-digit value: `parse()` would otherwise
        // accept a leading `+` and assorted Unicode whitespace/digits.
        let v = v.trim();
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(());
        }
        let parsed: usize = v.parse().map_err(|_| ())?;
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
    // Reject any bare CR or bare LF in the header block: every CR must be
    // immediately followed by LF and every LF immediately preceded by CR.
    // A stray `\n`/`\r` inside a field would otherwise enable request
    // smuggling / response splitting downstream (RFC 9112 §2.2).
    for (i, &b) in head.iter().enumerate() {
        if b == b'\r' {
            if head.get(i + 1) != Some(&b'\n') {
                return Err(Error::BadRequest("bare CR in header block"));
            }
        } else if b == b'\n' && (i == 0 || head[i - 1] != b'\r') {
            return Err(Error::BadRequest("bare LF in header block"));
        }
    }

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
        if headers.len() >= MAX_HEADER_FIELDS {
            return Err(Error::BadRequest("too many header fields"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(Error::BadRequest("header without colon"))?;
        // The field name must be a valid RFC 9110 token, validated on the
        // UNtrimmed name: whitespace between the name and the colon is illegal.
        if !is_token(name) {
            return Err(Error::BadRequest("invalid header name"));
        }
        let value = value.trim();
        if !is_valid_field_value(value) {
            return Err(Error::BadRequest("invalid header value"));
        }
        headers.append(name, value);
    }

    Ok((method, target.to_owned(), version, headers))
}

/// Incremental decoder for a chunked request body.
///
/// Unlike a one-shot decoder, this persists its progress (`pos`, the decoded
/// `out` accumulator, and the in-chunk `state`) across calls to [`advance`].
/// Each call resumes where the previous one stopped and only processes
/// newly-arrived bytes, so a body fed one byte at a time costs O(n) total work
/// rather than O(n²) from re-decoding the whole region every poll.
///
/// [`advance`]: ChunkDecoder::advance
#[derive(Debug, Default)]
struct ChunkDecoder {
    /// Bytes of the body region already consumed (parse cursor).
    pos: usize,
    /// Decoded body accumulated so far.
    out: Vec<u8>,
    /// What part of a chunk we are currently in.
    state: ChunkState,
}

/// The position within the chunked grammar that [`ChunkDecoder`] is resuming at.
#[derive(Debug, Default)]
enum ChunkState {
    /// Awaiting (the rest of) a chunk-size line.
    #[default]
    Size,
    /// In a chunk's data: `remaining` data bytes still to copy.
    Data { remaining: usize },
    /// Awaiting the CRLF that terminates a chunk's data.
    DataCrlf,
    /// In the trailer section that follows the terminating zero-length chunk;
    /// `start` is the body offset where the trailer section began (used to bound
    /// it against [`MAX_TRAILER_BYTES`]).
    Trailer { start: usize },
}

impl ChunkDecoder {
    /// Advance the decode over `data` (the full body region as buffered so far).
    ///
    /// Returns `Ok(Some(consumed))` once the terminating zero-length chunk and
    /// its trailer section have arrived (`consumed` is the number of body-region
    /// bytes the body occupies, and [`out`](Self::out) holds the decoded body),
    /// `Ok(None)` if more bytes are needed, or `Err(status)` on a malformed or
    /// oversized body. Every security check matches the one-shot decoder; only
    /// the incrementality differs.
    fn advance(
        &mut self,
        data: &[u8],
        max_body: usize,
    ) -> std::result::Result<Option<usize>, StatusCode> {
        loop {
            match self.state {
                ChunkState::Size => {
                    // Chunk size line. Bound how far we'll scan for its CRLF so a
                    // peer that never terminates the line (or pads it with
                    // megabytes of chunk extensions) cannot make us buffer
                    // without bound.
                    let eol = match find_subslice(&data[self.pos..], b"\r\n") {
                        Some(eol) => eol,
                        None => {
                            if data.len() - self.pos > MAX_CHUNK_LINE_BYTES {
                                return Err(StatusCode::BAD_REQUEST);
                            }
                            return Ok(None);
                        }
                    };
                    if eol > MAX_CHUNK_LINE_BYTES {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    let size_line = &data[self.pos..self.pos + eol];
                    // Strip any chunk extensions after ';'.
                    let hex = match size_line.iter().position(|&b| b == b';') {
                        Some(i) => &size_line[..i],
                        None => size_line,
                    };
                    let hex = std::str::from_utf8(hex).map_err(|_| StatusCode::BAD_REQUEST)?;
                    let hex = hex.trim();
                    // Require a non-empty run of hex digits: this both rejects
                    // garbage and surfaces a too-large value as a parse error
                    // rather than wrapping.
                    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    // A value that does not fit in usize (e.g. `fffffffffffffff0`
                    // on a 32-bit target, or 17+ hex digits anywhere) parses to
                    // Err here rather than overflowing.
                    let size =
                        usize::from_str_radix(hex, 16).map_err(|_| StatusCode::BAD_REQUEST)?;
                    // Cap a single chunk immediately: this both enforces the body
                    // limit and keeps every subsequent arithmetic operation far
                    // from overflow.
                    if size > max_body {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    let after_size = self.pos + eol + 2;

                    if size == 0 {
                        // Last chunk: consume the whole trailer section
                        // `*(field CRLF) CRLF` so trailer bytes are not left to be
                        // misread as the next request.
                        self.pos = after_size;
                        self.state = ChunkState::Trailer { start: after_size };
                        continue;
                    }

                    // Enforce the cumulative body limit with checked arithmetic.
                    match self.out.len().checked_add(size) {
                        Some(total) if total <= max_body => {}
                        _ => return Err(StatusCode::PAYLOAD_TOO_LARGE),
                    }
                    self.pos = after_size;
                    self.state = ChunkState::Data { remaining: size };
                }
                ChunkState::Data { remaining } => {
                    // Copy only the newly-arrived slice of this chunk's data; the
                    // already-copied prefix is never revisited.
                    let avail = data.len() - self.pos;
                    let take = remaining.min(avail);
                    self.out.extend_from_slice(&data[self.pos..self.pos + take]);
                    self.pos += take;
                    let left = remaining - take;
                    if left > 0 {
                        self.state = ChunkState::Data { remaining: left };
                        return Ok(None);
                    }
                    self.state = ChunkState::DataCrlf;
                }
                ChunkState::DataCrlf => {
                    // Each chunk's data is followed by a literal CRLF.
                    if data.len() < self.pos + 2 {
                        return Ok(None);
                    }
                    if &data[self.pos..self.pos + 2] != b"\r\n" {
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    self.pos += 2;
                    self.state = ChunkState::Size;
                }
                ChunkState::Trailer { start } => {
                    // Consume the trailer section `*(field CRLF) CRLF`, resuming at
                    // `self.pos`. Bounded against MAX_TRAILER_BYTES so a peer
                    // cannot stream trailers forever.
                    loop {
                        if self.pos.saturating_sub(start) > MAX_TRAILER_BYTES {
                            return Err(StatusCode::BAD_REQUEST);
                        }
                        match find_subslice(&data[self.pos..], b"\r\n") {
                            None => {
                                // Incomplete; bound how much we'll buffer waiting.
                                if data.len() - start > MAX_TRAILER_BYTES {
                                    return Err(StatusCode::BAD_REQUEST);
                                }
                                return Ok(None);
                            }
                            // An empty line terminates the trailer section.
                            Some(0) => return Ok(Some(self.pos + 2)),
                            // A trailer field line; skip it (trailers are not surfaced).
                            Some(eol) => self.pos += eol + 2,
                        }
                    }
                }
            }
        }
    }
}

/// Maximum number of header fields accepted in a single request.
const MAX_HEADER_FIELDS: usize = 100;

/// Maximum length of a single chunk-size line (size + extensions), in bytes.
const MAX_CHUNK_LINE_BYTES: usize = 16 * 1024;

/// Maximum size of the trailer section after the terminating zero-length chunk.
const MAX_TRAILER_BYTES: usize = 8 * 1024;

/// Hop-by-hop / framing headers that must never be forwarded from a handler's
/// response: the engine owns connection framing, so these are stripped before
/// serialization (RFC 9110 §7.6.1, plus the de-facto `proxy-connection`).
const HOP_BY_HOP_HEADERS: [&str; 7] = [
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "proxy-connection",
];

/// Whether `b` is an RFC 9110 `tchar` (a valid character in a `token`).
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Whether `s` is a non-empty RFC 9110 `token` (used for field names).
fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(is_tchar)
}

/// Whether `s` is a valid field value: no control characters (0x00-0x1F) other
/// than HTAB, and no DEL (0x7F). obs-text (0x80-0xFF) is permitted.
fn is_valid_field_value(s: &str) -> bool {
    s.bytes().all(|b| (b >= 0x20 && b != 0x7f) || b == b'\t')
}

/// Find the first occurrence of `needle` in `haystack`.
///
/// Scans for the needle's first byte and only then compares the full needle, so
/// for the short `\r\n` / `\r\n\r\n` needles used here it is a single linear
/// pass rather than the O(n·m) `windows().position()` it replaces.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let nlen = needle.len();
    if nlen == 0 || haystack.len() < nlen {
        return None;
    }
    let first = needle[0];
    let last_start = haystack.len() - nlen;
    let mut i = 0;
    while i <= last_start {
        // Jump straight to the next occurrence of the needle's first byte.
        match haystack[i..=last_start].iter().position(|&b| b == first) {
            Some(off) => {
                let cand = i + off;
                if haystack[cand..cand + nlen] == *needle {
                    return Some(cand);
                }
                i = cand + 1;
            }
            None => return None,
        }
    }
    None
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

    /// Write `data` to a fresh temp file and return it opened read-only.
    fn temp_file(data: &[u8]) -> Arc<File> {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!(
            "httpsd-h1-stream-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut f = File::create(&path).unwrap();
        f.write_all(data).unwrap();
        f.sync_all().unwrap();
        let opened = File::open(&path).unwrap();
        let _ = std::fs::remove_file(&path); // unlinked; fd keeps it alive
        Arc::new(opened)
    }

    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    /// Drain a connection's output fully (headers + every streamed body chunk),
    /// asserting it returns a result for each chunk while `has_output` is true.
    fn drain_all(conn: &mut H1Conn) -> Vec<u8> {
        let mut out = Vec::new();
        while conn.has_output() {
            let chunk = conn.take_out();
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        out
    }

    #[test]
    fn streams_multichunk_file_with_correct_length() {
        // Larger than STREAM_CHUNK so it must be served across several drains.
        let n = 5 * STREAM_CHUNK + 123;
        let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        let file = temp_file(&data);

        let mut c = H1Conn::default();
        let _ = drive(&mut c, b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
        c.respond(Response::new(StatusCode::OK).body(Body::file(file, 0, n as u64)));

        let out = drain_all(&mut c);
        let split = find_subslice(&out, b"\r\n\r\n").unwrap() + 4;
        let head = String::from_utf8(out[..split].to_vec()).unwrap();
        assert!(
            head.contains(&format!("Content-Length: {n}\r\n")),
            "head: {head}"
        );
        assert_eq!(&out[split..], &data[..], "streamed body must be byte-exact");
    }

    #[test]
    fn streams_file_range_span_only() {
        let data: Vec<u8> = (0..(2 * STREAM_CHUNK)).map(|i| (i % 256) as u8).collect();
        let file = temp_file(&data);
        let (start, len) = (1000u64, (STREAM_CHUNK + 7) as u64);

        let mut c = H1Conn::default();
        let _ = drive(&mut c, b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
        c.respond(Response::new(StatusCode::PARTIAL_CONTENT).body(Body::file(file, start, len)));

        let out = drain_all(&mut c);
        let split = find_subslice(&out, b"\r\n\r\n").unwrap() + 4;
        assert_eq!(
            &out[split..],
            &data[start as usize..(start + len) as usize],
            "range body must be exactly the requested span"
        );
    }

    #[test]
    fn head_file_sends_length_but_no_body() {
        let data = vec![7u8; 3 * STREAM_CHUNK];
        let file = temp_file(&data);

        let mut c = H1Conn::default();
        let _ = drive(&mut c, b"HEAD / HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
        c.respond(Response::new(StatusCode::OK).body(Body::file(file, 0, data.len() as u64)));

        let out = drain_all(&mut c);
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains(&format!("Content-Length: {}\r\n", data.len())),
            "head: {text}"
        );
        assert!(text.ends_with("\r\n\r\n"), "HEAD must send no body: {text}");
    }

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
    fn chunked_with_real_trailer_parses_and_drains() {
        let mut c = H1Conn::default();
        let req = drive(
            &mut c,
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nA: 1\r\n\r\n",
        )
        .unwrap();
        assert_eq!(req.body(), b"hello");
        // The trailer must be fully consumed: nothing left to misparse.
        assert!(c.inbuf.is_empty());
    }

    #[test]
    fn chunked_partial_trailer_waits() {
        let mut c = H1Conn::default();
        // Final empty line (CRLF terminating the trailer section) not yet sent.
        c.feed(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nA: 1\r\n");
        assert!(c.poll_request().unwrap().is_none());
        c.feed(b"\r\n");
        let req = c.poll_request().unwrap().unwrap();
        assert_eq!(req.body(), b"hello");
        assert!(c.inbuf.is_empty());
    }

    #[test]
    fn chunked_trailer_bytes_not_smuggled_as_next_request() {
        let mut c = H1Conn::default();
        // Without proper trailer consumption the `GET /evil` line would be left
        // in the buffer and parsed as a second request.
        c.feed(
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
              0\r\nX: y\r\n\r\nGET /evil HTTP/1.1\r\nHost: a\r\n\r\n",
        );
        let _ = c.poll_request().unwrap().unwrap();
        c.respond(Response::text("ok"));
        let next = c.poll_request().unwrap().unwrap();
        // The smuggled request is parsed only because the client legitimately
        // pipelined it after a *complete* trailer section.
        assert_eq!(next.path(), "/evil");
    }

    #[test]
    fn chunked_huge_size_is_rejected_not_panicking() {
        let mut c = H1Conn::default();
        c.feed(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffff0\r\n");
        let err = c.poll_request();
        assert!(err.is_err());
        let out = String::from_utf8(c.take_out()).unwrap();
        assert!(out.starts_with("HTTP/1.1 413"));
    }

    #[test]
    fn chunked_non_hex_size_is_rejected() {
        let mut c = H1Conn::default();
        c.feed(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n");
        assert!(c.poll_request().is_err());
    }

    #[test]
    fn chunked_oversized_size_line_is_rejected() {
        let mut c = H1Conn::default();
        c.feed(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        // A chunk-size line with a never-ending extension and no CRLF.
        let mut huge = b"1;".to_vec();
        huge.extend(std::iter::repeat_n(b'a', MAX_CHUNK_LINE_BYTES + 16));
        c.feed(&huge);
        assert!(c.poll_request().is_err());
    }

    #[test]
    fn rejects_bare_lf_in_headers() {
        let mut c = H1Conn::default();
        // Bare LF after the Host value, then the proper terminator.
        c.feed(b"GET / HTTP/1.1\r\nHost: a\nX: y\r\n\r\n");
        assert!(c.poll_request().is_err());
    }

    #[test]
    fn rejects_control_char_in_header_value() {
        let mut c = H1Conn::default();
        c.feed(b"GET / HTTP/1.1\r\nX: a\x01b\r\n\r\n");
        assert!(c.poll_request().is_err());
    }

    #[test]
    fn rejects_non_token_header_name() {
        let mut c = H1Conn::default();
        c.feed(b"GET / HTTP/1.1\r\nBad Name: x\r\n\r\n");
        assert!(c.poll_request().is_err());
    }

    #[test]
    fn rejects_too_many_header_fields() {
        let mut c = H1Conn::default();
        let mut req = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..(MAX_HEADER_FIELDS + 5) {
            req.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
        }
        req.extend_from_slice(b"\r\n");
        c.feed(&req);
        assert!(c.poll_request().is_err());
    }

    #[test]
    fn rejects_non_digit_content_length() {
        let mut c = H1Conn::default();
        c.feed(b"POST / HTTP/1.1\r\nContent-Length: +5\r\n\r\nhello");
        assert!(c.poll_request().is_err());
    }

    #[test]
    fn serialize_strips_handler_transfer_encoding_and_injection() {
        let mut c = H1Conn::default();
        let _ = drive(&mut c, b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
        let mut resp = Response::text("hi");
        resp.headers_mut().set("Transfer-Encoding", "chunked");
        resp.headers_mut().set("X-Evil", "a\r\nInjected: 1");
        c.respond(resp);
        let out = String::from_utf8(c.take_out()).unwrap();
        assert!(!out.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(!out.contains("Injected: 1"));
        assert!(out.contains("Content-Length: 2\r\n"));
    }

    #[test]
    fn chunked_byte_by_byte_matches_all_at_once() {
        // A body with multiple chunks, a chunk extension, and a real trailer.
        let req_bytes: &[u8] = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
            5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX: y\r\n\r\n";

        // All at once.
        let mut c_all = H1Conn::default();
        c_all.feed(req_bytes);
        let req_all = c_all.poll_request().unwrap().unwrap();
        assert_eq!(req_all.body(), b"hello world");
        assert!(c_all.inbuf.is_empty());

        // One byte at a time: must yield the identical parse and leave inbuf clean.
        let mut c_inc = H1Conn::default();
        let mut got = None;
        for &b in req_bytes {
            c_inc.feed(&[b]);
            if let Some(r) = c_inc.poll_request().unwrap() {
                got = Some(r);
            }
        }
        let req_inc = got.expect("incremental feed never completed the request");
        assert_eq!(req_inc.body(), req_all.body());
        assert_eq!(req_inc.method(), req_all.method());
        assert_eq!(req_inc.path(), req_all.path());
        assert!(
            c_inc.inbuf.is_empty(),
            "inbuf must be drained clean after incremental parse"
        );
        // The decode state must have been cleared once the request completed.
        assert!(c_inc.chunk.is_none());
        assert_eq!(c_inc.head_scanned, 0);
    }

    #[test]
    fn large_header_block_byte_by_byte_parses() {
        let mut req = b"GET / HTTP/1.1\r\n".to_vec();
        // ~40 KiB of header fields, under both the 64 KiB byte cap and the
        // MAX_HEADER_FIELDS count cap.
        for i in 0..50 {
            req.extend_from_slice(format!("X-Pad-{i}: {}\r\n", "v".repeat(800)).as_bytes());
        }
        req.extend_from_slice(b"Host: a\r\n\r\n");

        let mut c = H1Conn::default();
        let mut got = None;
        for &b in &req {
            c.feed(&[b]);
            if let Some(r) = c.poll_request().unwrap() {
                got = Some(r);
            }
        }
        let req = got.expect("terminator never found under byte-by-byte feed");
        assert_eq!(req.method(), &Method::Get);
        assert_eq!(req.host(), Some("a"));
        assert!(c.inbuf.is_empty());
    }

    #[test]
    fn chunked_huge_size_rejected_under_incremental_feed() {
        let bytes: &[u8] =
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffff0\r\n";
        let mut c = H1Conn::default();
        let mut err = false;
        for &b in bytes {
            c.feed(&[b]);
            match c.poll_request() {
                Ok(_) => {}
                Err(_) => {
                    err = true;
                    break;
                }
            }
        }
        assert!(err, "malicious chunk size must be rejected (no panic)");
        let out = String::from_utf8(c.take_out()).unwrap();
        assert!(out.starts_with("HTTP/1.1 413"));
    }

    #[test]
    fn chunked_large_body_byte_by_byte_completes() {
        // A bounded-work proof: an O(n²) re-decode of a 200 KiB body fed one byte
        // at a time would be ~40 billion byte-copies; the incremental decoder
        // copies each body byte exactly once, so this finishes promptly.
        const N: usize = 200 * 1024;
        let mut body = Vec::with_capacity(N);
        for i in 0..N {
            body.push(b'a' + (i % 26) as u8);
        }
        let mut req = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        req.extend_from_slice(format!("{:x}\r\n", N).as_bytes());
        req.extend_from_slice(&body);
        req.extend_from_slice(b"\r\n0\r\n\r\n");

        let mut c = H1Conn::default();
        let mut got = None;
        for &b in &req {
            c.feed(&[b]);
            if let Some(r) = c.poll_request().unwrap() {
                got = Some(r);
            }
        }
        let req = got.expect("large chunked body never completed");
        assert_eq!(req.body().len(), N);
        assert_eq!(req.body(), &body[..]);
        assert!(c.inbuf.is_empty());
    }

    #[test]
    fn find_subslice_linear_correctness() {
        assert_eq!(find_subslice(b"", b"\r\n"), None);
        assert_eq!(find_subslice(b"\r\n", b"\r\n"), Some(0));
        assert_eq!(find_subslice(b"ab\r\ncd", b"\r\n"), Some(2));
        assert_eq!(find_subslice(b"a\rb\r\nc", b"\r\n"), Some(3));
        assert_eq!(find_subslice(b"x\r\n\r\ny", b"\r\n\r\n"), Some(1));
        assert_eq!(find_subslice(b"\r\n\r", b"\r\n\r\n"), None);
        assert_eq!(find_subslice(b"abc", b"abc"), Some(0));
        assert_eq!(find_subslice(b"aabc", b"abc"), Some(1));
        assert_eq!(find_subslice(b"ab", b"abc"), None);
        assert_eq!(find_subslice(b"hello", b"l"), Some(2));
        assert_eq!(find_subslice(b"hello", b""), None);
    }

    #[test]
    fn http_date_known_value() {
        // 784111777 = Sun, 06 Nov 1994 08:49:37 GMT
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    }
}
