//! HTTP responses produced by handlers.

use std::fs::File;
use std::sync::Arc;

use super::stream::{self, BodySender, StreamPoll, StreamReceiver, Waker};
use super::{Headers, StatusCode};

/// Bytes pulled from a file per drain when streaming a [`Body::File`]. Bounds
/// the working-set so serving a large file never buffers more than this at once.
pub(crate) const STREAM_CHUNK: usize = 64 * 1024;

/// The body of a response.
///
/// A body is one of:
///
/// - buffered bytes — build it from a `Vec<u8>`, `&[u8]`, `String` or `&str`
///   via the `From` impls;
/// - a region of an open file ([`Body::file`] / [`Body::from_file`]), which
///   the engines stream in bounded chunks instead of reading into memory;
/// - a stream ([`Body::channel`]) whose bytes are produced while the response
///   is being sent, for incremental output, long polling or server-sent
///   events.
///
/// Cloning a file body shares the descriptor and cloning a stream body shares
/// the stream (via `Arc`), so [`Response`] stays cheap to clone.
#[derive(Debug, Clone)]
pub struct Body {
    inner: BodyInner,
}

#[derive(Debug, Clone)]
enum BodyInner {
    /// A fully-buffered byte body.
    Bytes(Vec<u8>),
    /// A `len`-byte region of `file` starting at `offset`, streamed on demand
    /// using positioned reads (so `offset` is honored without a shared cursor).
    File {
        file: Arc<File>,
        offset: u64,
        len: u64,
    },
    /// Bytes produced while the response is sent, length unknown up front.
    Stream(Arc<StreamReceiver>),
}

/// Owned, destructured view of a [`Body`] for the engines, which must decide
/// whether to buffer or stream. Kept `pub(crate)` so the public `Body` API is
/// unaffected by the streaming machinery.
pub(crate) enum BodyKind {
    Bytes(Vec<u8>),
    File {
        file: Arc<File>,
        offset: u64,
        len: u64,
    },
    Stream(Arc<StreamReceiver>),
}

impl Default for Body {
    fn default() -> Body {
        Body::empty()
    }
}

impl Body {
    /// An empty body.
    pub fn empty() -> Body {
        Body {
            inner: BodyInner::Bytes(Vec::new()),
        }
    }

    /// The body bytes, for a buffered body. A file or stream body yields an
    /// empty slice (its bytes are produced while the response is sent).
    pub fn as_bytes(&self) -> &[u8] {
        match &self.inner {
            BodyInner::Bytes(b) => b,
            BodyInner::File { .. } | BodyInner::Stream(_) => &[],
        }
    }

    /// The body length in bytes. A stream body's length is unknown, so it
    /// reports 0; check [`is_stream`](Self::is_stream) first if that matters.
    pub fn len(&self) -> usize {
        self.len_u64() as usize
    }

    /// Whether the body is known to be empty. Always `false` for a stream.
    pub fn is_empty(&self) -> bool {
        !self.is_stream() && self.len_u64() == 0
    }

    /// A body streamed from `len` bytes of `file` starting at `offset`.
    ///
    /// The engines read the region in bounded chunks with positioned reads, so
    /// the file is never loaded into memory and the descriptor's own cursor is
    /// never moved (one `Arc<File>` can back several responses at once). `len`
    /// is sent as the `Content-Length`; if the file turns out shorter, the
    /// response is aborted (connection closed or stream reset) rather than sent
    /// with the wrong length.
    pub fn file(file: Arc<File>, offset: u64, len: u64) -> Body {
        Body {
            inner: BodyInner::File { file, offset, len },
        }
    }

    /// A body streaming the whole of `file`, from its start to its current
    /// length.
    pub fn from_file(file: File) -> std::io::Result<Body> {
        let len = file.metadata()?.len();
        Ok(Body::file(Arc::new(file), 0, len))
    }

    /// A streamed body plus the [`BodySender`] that produces it.
    ///
    /// Return the body in a response, keep the sender (typically in a thread
    /// the handler starts), and write to it: each write reaches the client as
    /// soon as the connection can take it. The response headers go out right
    /// away. On HTTP/1.1 the body is sent with `Transfer-Encoding: chunked`; on
    /// HTTP/1.0 it is sent raw and the connection is closed at the end; on
    /// HTTP/2 and HTTP/3 each write becomes DATA. A `Content-Length` set by the
    /// handler is ignored, and stream bodies are never compressed.
    ///
    /// ```no_run
    /// use httpsd::{Body, Request, Response};
    ///
    /// fn events(_req: &Request) -> Response {
    ///     let (tx, body) = Body::channel();
    ///     std::thread::spawn(move || {
    ///         for i in 0..10 {
    ///             if tx.send(format!("data: tick {i}\n\n")).is_err() {
    ///                 return; // client went away
    ///             }
    ///             std::thread::sleep(std::time::Duration::from_secs(1));
    ///         }
    ///     });
    ///     Response::new(httpsd::StatusCode::OK)
    ///         .header("Content-Type", "text/event-stream")
    ///         .body(body)
    /// }
    /// ```
    pub fn channel() -> (BodySender, Body) {
        let (tx, rx) = stream::channel();
        (
            tx,
            Body {
                inner: BodyInner::Stream(Arc::new(rx)),
            },
        )
    }

    /// Whether this body is a stream created by [`Body::channel`].
    pub fn is_stream(&self) -> bool {
        matches!(self.inner, BodyInner::Stream(_))
    }

    /// Whether this body is a region of a file created by [`Body::file`].
    pub fn is_file(&self) -> bool {
        matches!(self.inner, BodyInner::File { .. })
    }

    /// The body length as a `u64` (a file body can exceed `usize` on 32-bit).
    /// 0 for a stream.
    pub(crate) fn len_u64(&self) -> u64 {
        match &self.inner {
            BodyInner::Bytes(b) => b.len() as u64,
            BodyInner::File { len, .. } => *len,
            BodyInner::Stream(_) => 0,
        }
    }

    /// Register the callback fired when a stream body has new data. No-op for
    /// other bodies.
    pub(crate) fn set_waker(&self, waker: Option<&Waker>) {
        if let (BodyInner::Stream(rx), Some(w)) = (&self.inner, waker) {
            rx.set_waker(Arc::clone(w));
        }
    }

    /// Destructure into the engine-facing view.
    pub(crate) fn into_kind(self) -> BodyKind {
        match self.inner {
            BodyInner::Bytes(b) => BodyKind::Bytes(b),
            BodyInner::File { file, offset, len } => BodyKind::File { file, offset, len },
            BodyInner::Stream(rx) => BodyKind::Stream(rx),
        }
    }

    /// Materialize the body into a byte vector.
    ///
    /// For a buffered body this hands back the buffer. For a file body it reads
    /// the region into memory, and for a stream it blocks until the producer
    /// finishes (so this must NOT be called on the streaming/compression hot
    /// path — see [`crate::compress`]); a read error or an aborted stream
    /// yields an empty vector rather than panicking.
    #[cfg_attr(not(any(feature = "compress", feature = "http")), allow(dead_code))]
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        match self.inner {
            BodyInner::Bytes(b) => b,
            BodyInner::File { file, offset, len } => {
                let mut buf = vec![0u8; len as usize];
                match read_at_exact(&file, offset, &mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        buf
                    }
                    Err(_) => Vec::new(),
                }
            }
            BodyInner::Stream(rx) => rx.collect_blocking().unwrap_or_default(),
        }
    }
}

impl From<Vec<u8>> for Body {
    fn from(bytes: Vec<u8>) -> Body {
        Body {
            inner: BodyInner::Bytes(bytes),
        }
    }
}

impl From<&[u8]> for Body {
    fn from(bytes: &[u8]) -> Body {
        Body {
            inner: BodyInner::Bytes(bytes.to_vec()),
        }
    }
}

impl From<String> for Body {
    fn from(s: String) -> Body {
        Body {
            inner: BodyInner::Bytes(s.into_bytes()),
        }
    }
}

impl From<&str> for Body {
    fn from(s: &str) -> Body {
        Body {
            inner: BodyInner::Bytes(s.as_bytes().to_vec()),
        }
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

/// What a send-side body can hand out right now.
#[cfg(any(feature = "h2", feature = "h3"))]
pub(crate) enum Avail {
    /// This many bytes can be taken with [`OutBody::take_chunk`].
    Data(u64),
    /// A stream with nothing ready yet.
    Pending,
    /// Every byte has been taken.
    End,
    /// A stream whose producer aborted.
    Failed,
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
    /// A producer-fed stream; `buf[pos..]` is data received but not yet taken.
    Stream {
        rx: Arc<StreamReceiver>,
        buf: Vec<u8>,
        pos: usize,
        ended: bool,
    },
}

#[cfg(any(feature = "h2", feature = "h3"))]
impl OutBody {
    /// Build a send-side body from a response [`Body`].
    pub(crate) fn from_body(body: Body) -> OutBody {
        match body.into_kind() {
            BodyKind::Bytes(data) => OutBody::Bytes { data, pos: 0 },
            BodyKind::File { file, offset, len } => OutBody::File {
                file,
                offset,
                remaining: len,
            },
            BodyKind::Stream(rx) => OutBody::Stream {
                rx,
                buf: Vec::new(),
                pos: 0,
                ended: false,
            },
        }
    }

    /// Whether this is a producer-fed stream (length unknown up front).
    pub(crate) fn is_stream(&self) -> bool {
        matches!(self, OutBody::Stream { .. })
    }

    /// Whether there is (or, for a stream, may be) any body to send. False for
    /// an empty sized body, whose END_STREAM can ride on the headers.
    pub(crate) fn has_body(&self) -> bool {
        match self {
            OutBody::Bytes { data, pos } => *pos < data.len(),
            OutBody::File { remaining, .. } => *remaining > 0,
            OutBody::Stream { .. } => true,
        }
    }

    /// Whether a stream is still waiting on its producer.
    pub(crate) fn is_pending_stream(&self) -> bool {
        matches!(self, OutBody::Stream { ended: false, .. })
    }

    /// For a sized body: whether taking `n` more bytes completes it. Always
    /// false for a stream (its end is only known once the producer finishes).
    pub(crate) fn is_last(&self, n: u64) -> bool {
        match self {
            OutBody::Bytes { data, pos } => (data.len() - *pos) as u64 == n,
            OutBody::File { remaining, .. } => *remaining == n,
            OutBody::Stream { .. } => false,
        }
    }

    /// How much can be taken right now (polling the producer for a stream).
    pub(crate) fn poll_avail(&mut self) -> Avail {
        match self {
            OutBody::Bytes { data, pos } if *pos < data.len() => {
                Avail::Data((data.len() - *pos) as u64)
            }
            OutBody::File { remaining, .. } if *remaining > 0 => Avail::Data(*remaining),
            OutBody::Bytes { .. } | OutBody::File { .. } => Avail::End,
            OutBody::Stream {
                rx,
                buf,
                pos,
                ended,
            } => {
                if *pos < buf.len() {
                    return Avail::Data((buf.len() - *pos) as u64);
                }
                if *ended {
                    return Avail::End;
                }
                match rx.poll(STREAM_CHUNK) {
                    StreamPoll::Data(d) => {
                        *buf = d;
                        *pos = 0;
                        Avail::Data(buf.len() as u64)
                    }
                    StreamPoll::Pending => Avail::Pending,
                    StreamPoll::End => {
                        *ended = true;
                        Avail::End
                    }
                    StreamPoll::Aborted => {
                        *ended = true;
                        Avail::Failed
                    }
                }
            }
        }
    }

    /// Take the next `n` bytes, where `n` is at most what [`poll_avail`]
    /// reported (positioned read for a file). Returns `Err(())` if a file read
    /// fails or comes up short (the file shrank) — the caller should
    /// reset/abort that stream rather than send a truncated, mis-framed body.
    ///
    /// [`poll_avail`]: Self::poll_avail
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
            OutBody::Stream { buf, pos, .. } => {
                let start = *pos;
                *pos += n;
                Ok(buf[start..start + n].to_vec())
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
    /// A reason phrase overriding the status's default, if set.
    reason: Option<String>,
    headers: Headers,
    body: Body,
}

impl Response {
    /// A response with the given status, no headers, and an empty body.
    pub fn new(status: StatusCode) -> Response {
        Response {
            status,
            reason: None,
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

    /// Override the status code (builder style), keeping headers and body. A
    /// custom reason phrase set earlier with
    /// [`with_reason`](Self::with_reason) is cleared, since it described the
    /// old status.
    pub fn with_status(mut self, status: StatusCode) -> Response {
        self.status = status;
        self.reason = None;
        self
    }

    /// Set a custom reason phrase for the status line (builder style), e.g.
    /// `HTTP/1.1 299 My Reason`. Only HTTP/1.x has reason phrases; HTTP/2 and
    /// HTTP/3 send just the code. A phrase containing control characters (such
    /// as CR or LF) is not sent: the status's default phrase is used instead.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Response {
        self.reason = Some(reason.into());
        self
    }

    /// The reason phrase to send: the custom one if set, else the status's
    /// default.
    pub fn reason(&self) -> &str {
        self.reason.as_deref().unwrap_or(self.status.reason())
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

    /// Remove and return the custom reason phrase, if any.
    pub(crate) fn take_reason(&mut self) -> Option<String> {
        self.reason.take()
    }

    /// Remove and return the body, leaving an empty one.
    #[cfg_attr(not(feature = "compress"), allow(dead_code))]
    pub(crate) fn take_body(&mut self) -> Body {
        std::mem::take(&mut self.body)
    }

    // Used by the compression and `http`-interop layers to rebuild a response.
    #[cfg_attr(not(any(feature = "compress", feature = "http")), allow(dead_code))]
    pub(crate) fn from_parts(status: StatusCode, headers: Headers, body: Body) -> Response {
        Response {
            status,
            reason: None,
            headers,
            body,
        }
    }
}
