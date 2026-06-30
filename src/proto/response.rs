//! HTTP responses produced by handlers.

use std::fs::File;
use std::sync::Arc;

use super::{Headers, StatusCode};

/// Bytes pulled from a file per drain when streaming a [`Body::File`]. Bounds
/// the working-set so serving a large file never buffers more than this at once.
pub(crate) const STREAM_CHUNK: usize = 64 * 1024;

/// The body of a response.
///
/// A body is either a buffered byte vector ([`Body::Bytes`]) or a region of an
/// open file ([`Body::File`]) that the engines stream in bounded chunks instead
/// of reading into memory. Cloning a `File` body shares the underlying file
/// descriptor (via `Arc`), so [`Response`] stays cheap to clone.
#[derive(Debug, Clone)]
pub enum Body {
    /// A fully-buffered byte body.
    Bytes(Vec<u8>),
    /// A `len`-byte region of `file` starting at `offset`, streamed on demand
    /// using positioned reads (so `offset` is honored without a shared cursor).
    File {
        /// The open file, shared so cloning the body shares the descriptor.
        file: Arc<File>,
        /// Absolute byte offset of the region's start within the file.
        offset: u64,
        /// Number of bytes to serve from `offset`.
        len: u64,
    },
}

impl Default for Body {
    fn default() -> Body {
        Body::empty()
    }
}

impl Body {
    /// An empty body.
    pub fn empty() -> Body {
        Body::Bytes(Vec::new())
    }

    /// A body streamed from `len` bytes of `file` starting at `offset`.
    pub fn file(file: Arc<File>, offset: u64, len: u64) -> Body {
        Body::File { file, offset, len }
    }

    /// The body bytes, for a buffered body. A [`Body::File`] yields an empty
    /// slice (its bytes live on disk; use the streaming engines to send them).
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Body::Bytes(b) => b,
            Body::File { .. } => &[],
        }
    }

    /// The body length in bytes.
    pub fn len(&self) -> u64 {
        match self {
            Body::Bytes(b) => b.len() as u64,
            Body::File { len, .. } => *len,
        }
    }

    /// Whether the body is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Materialize the body into a byte vector.
    ///
    /// For a [`Body::Bytes`] this just hands back the buffer. For a
    /// [`Body::File`] it reads the region into memory (so this must NOT be called
    /// on the streaming/compression hot path — see [`crate::compress`]); a read
    /// error yields an empty vector rather than panicking.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        match self {
            Body::Bytes(b) => b,
            Body::File { file, offset, len } => {
                let mut buf = vec![0u8; len as usize];
                match read_at_exact(&file, offset, &mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        buf
                    }
                    Err(_) => Vec::new(),
                }
            }
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Body {
        Body::Bytes(bytes)
    }
}

impl From<&[u8]> for Body {
    fn from(bytes: &[u8]) -> Body {
        Body::Bytes(bytes.to_vec())
    }
}

impl From<String> for Body {
    fn from(s: String) -> Body {
        Body::Bytes(s.into_bytes())
    }
}

impl From<&str> for Body {
    fn from(s: &str) -> Body {
        Body::Bytes(s.as_bytes().to_vec())
    }
}

/// Positioned read of one byte at `offset`-relative position into `buf`.
///
/// Uses the platform positioned-read syscall so the file's own cursor is never
/// touched (no shared-cursor race when an `Arc<File>` is streamed) and `offset`
/// is always honored.
#[cfg(unix)]
fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buf, offset)
}

/// Read up to `buf.len()` bytes starting at `offset`, retrying short reads.
///
/// Returns the number of bytes read; a value below `buf.len()` means EOF was hit
/// (the file is shorter than expected, e.g. it shrank under us). Honors `offset`
/// via [`read_at`] so it is safe to call concurrently on a shared `Arc<File>`.
pub(crate) fn read_at_exact(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match read_at(file, offset + total as u64, &mut buf[total..]) {
            Ok(0) => break, // EOF / file shrank
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Send-side view of a response body the multiplexed engines (HTTP/2, HTTP/3)
/// stream out incrementally as flow control allows.
#[cfg(any(feature = "h2", feature = "h3"))]
pub(crate) enum OutBody {
    /// Buffered bytes, with the offset already written.
    Bytes { data: Vec<u8>, pos: usize },
    /// A file region: `offset` is the next byte to read, `remaining` what is left.
    File {
        file: Arc<File>,
        offset: u64,
        remaining: u64,
    },
}

#[cfg(any(feature = "h2", feature = "h3"))]
impl OutBody {
    /// Build a send-side body from a response [`Body`].
    pub(crate) fn from_body(body: Body) -> OutBody {
        match body {
            Body::Bytes(data) => OutBody::Bytes { data, pos: 0 },
            Body::File { file, offset, len } => OutBody::File {
                file,
                offset,
                remaining: len,
            },
        }
    }

    /// Bytes still to send.
    pub(crate) fn remaining(&self) -> u64 {
        match self {
            OutBody::Bytes { data, pos } => (data.len() - *pos) as u64,
            OutBody::File { remaining, .. } => *remaining,
        }
    }

    /// Take the next `n` bytes (positioned read for a file). Returns `Err(())` if
    /// a file read fails or comes up short (the file shrank) — the caller should
    /// reset/abort that stream rather than send a truncated, mis-framed body.
    pub(crate) fn take_chunk(&mut self, n: usize) -> Result<Vec<u8>, ()> {
        match self {
            OutBody::Bytes { data, pos } => {
                let start = *pos;
                *pos += n;
                Ok(data[start..start + n].to_vec())
            }
            OutBody::File {
                file,
                offset,
                remaining,
            } => {
                let mut buf = vec![0u8; n];
                match read_at_exact(file, *offset, &mut buf) {
                    Ok(got) if got == n => {
                        *offset += n as u64;
                        *remaining -= n as u64;
                        Ok(buf)
                    }
                    _ => Err(()),
                }
            }
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

    pub(crate) fn into_parts(self) -> (StatusCode, Headers, Body) {
        (self.status, self.headers, self.body)
    }

    // Used by the compression and `http`-interop layers to rebuild a response.
    #[cfg_attr(not(any(feature = "compress", feature = "http")), allow(dead_code))]
    pub(crate) fn from_parts(status: StatusCode, headers: Headers, body: Body) -> Response {
        Response {
            status,
            headers,
            body,
        }
    }
}
