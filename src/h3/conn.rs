//! The HTTP/3 application layer (RFC 9114), driven over one
//! [`QuicConnection`](purecrypto::quic::QuicConnection).
//!
//! [`H3Conn`] holds the per-connection HTTP/3 state — the QPACK coders and the
//! in-progress request streams — and a [`drive`](H3Conn::drive) method that the
//! QUIC runtime calls after every datagram exchange. Unlike the HTTP/1 and
//! HTTP/2 engines (which only shuffle bytes), `drive` also invokes the handler,
//! because HTTP/3 requests and responses are scoped to QUIC streams the engine
//! manages directly.

use std::collections::BTreeMap;

use compcol::hpack::HeaderField;
use compcol::qpack::{QpackDecoder, QpackEncoder};
use purecrypto::quic::{QuicConnection, StreamId};

use crate::error::Result;
use crate::proto::{Limits, OutBody, Request, Response, Version, request_head, response_fields};
use crate::session::SessionConfig;

#[cfg(feature = "compress")]
use crate::compress;

// HTTP/3 frame types (RFC 9114 §7.2).
const FRAME_DATA: u64 = 0x0;
const FRAME_HEADERS: u64 = 0x1;
const FRAME_SETTINGS: u64 = 0x4;

// Unidirectional stream types (RFC 9114 §6.2 / RFC 9204 §4.2).
const STREAM_CONTROL: u64 = 0x0;
const STREAM_QPACK_ENCODER: u64 = 0x2;
const STREAM_QPACK_DECODER: u64 = 0x3;

// SETTINGS identifiers (RFC 9114 §7.2.4.1 / RFC 9204 §5).
const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;

// HTTP/3 error codes used for stream resets.
const H3_REQUEST_INCOMPLETE: u64 = 0x010d;
const H3_MESSAGE_ERROR: u64 = 0x010e;

/// Cap on concurrently-tracked request streams per connection. QUIC's
/// `initial_max_streams_bidi` already bounds how many bidi streams a peer may
/// have open at once, but a peer can reset/abandon streams and open fresh ones
/// faster than we'd otherwise drop the state, and resets must not leak entries.
/// This is a hard backstop on the size of `reqs`; it sits well above the
/// advertised bidi-stream limit so legitimate clients are never affected.
const MAX_REQ_STREAMS: usize = 256;

/// Bytes of a file body framed into a single DATA frame per flush step, so a
/// large file is streamed as QUIC stream send capacity opens rather than
/// buffered whole.
const H3_STREAM_CHUNK: usize = 64 * 1024;

/// In-progress state for one client-initiated bidirectional (request) stream.
#[derive(Default)]
struct ReqStream {
    inbuf: Vec<u8>,
    fin: bool,
    delivered: bool,
    /// Already-framed response bytes awaiting the QUIC send buffer.
    out: Vec<u8>,
    out_pos: usize,
    /// Response body still to frame as DATA (streamed incrementally).
    body: Option<OutBody>,
    finish_after: bool,
    finished: bool,
}

/// The HTTP/3 state for one connection.
pub struct H3Conn {
    limits: Limits,
    server_name: Option<String>,
    qpack_enc: QpackEncoder,
    qpack_dec: QpackDecoder,
    started: bool,
    control_stream: Option<u64>,
    reqs: BTreeMap<u64, ReqStream>,
}

impl H3Conn {
    /// Create the HTTP/3 state for a freshly accepted QUIC connection.
    pub fn new(limits: Limits, server_name: Option<String>) -> H3Conn {
        H3Conn {
            limits,
            server_name,
            qpack_enc: QpackEncoder::new(),
            qpack_dec: QpackDecoder::new(),
            started: false,
            control_stream: None,
            reqs: BTreeMap::new(),
        }
    }

    /// Service the connection: open our streams once the handshake completes,
    /// read newly readable streams, run the handler for any completed request,
    /// and write out responses (subject to QUIC flow control).
    pub fn drive(&mut self, quic: &mut QuicConnection, cfg: &SessionConfig) -> Result<()> {
        if !quic.is_handshake_complete() {
            return Ok(());
        }
        self.start(quic)?;

        let ids: Vec<u64> = quic.readable_streams().map(|s| s.value()).collect();
        for id in ids {
            match id & 0x3 {
                0x0 => self.read_request(quic, id), // client-initiated bidi
                0x2 => drain_stream(quic, id),      // client-initiated uni (control/qpack)
                _ => {}
            }
        }

        // Run the handler for each fully-received request.
        let ready: Vec<u64> = self
            .reqs
            .iter()
            .filter(|(_, r)| r.fin && !r.delivered)
            .map(|(id, _)| *id)
            .collect();
        for id in ready {
            self.handle_request(quic, id, cfg);
        }

        self.flush(quic)?;
        Ok(())
    }

    /// Open our control + QPACK streams and send SETTINGS, once.
    fn start(&mut self, quic: &mut QuicConnection) -> Result<()> {
        if self.started {
            return Ok(());
        }
        // Control stream: type byte + a SETTINGS frame advertising a stateless
        // QPACK (zero dynamic table, no blocked streams).
        let control = quic.open_uni().map_err(qerr)?;
        let mut payload = Vec::new();
        write_varint(&mut payload, SETTINGS_QPACK_MAX_TABLE_CAPACITY);
        write_varint(&mut payload, 0);
        write_varint(&mut payload, SETTINGS_QPACK_BLOCKED_STREAMS);
        write_varint(&mut payload, 0);
        write_varint(&mut payload, SETTINGS_MAX_FIELD_SECTION_SIZE);
        write_varint(&mut payload, self.limits.max_header_bytes as u64);

        let mut control_bytes = Vec::new();
        write_varint(&mut control_bytes, STREAM_CONTROL);
        write_frame(&mut control_bytes, FRAME_SETTINGS, &payload);
        write_all(quic, control, &control_bytes)?;
        self.control_stream = Some(control.value());

        // QPACK encoder/decoder streams: just the type byte (we never send
        // dynamic-table instructions).
        for ty in [STREAM_QPACK_ENCODER, STREAM_QPACK_DECODER] {
            let s = quic.open_uni().map_err(qerr)?;
            let mut b = Vec::new();
            write_varint(&mut b, ty);
            write_all(quic, s, &b)?;
        }

        self.started = true;
        Ok(())
    }

    fn read_request(&mut self, quic: &mut QuicConnection, id: u64) {
        let (data, fin) = read_stream(quic, id);
        if data.is_empty() && !fin {
            // The stream was reported readable yet yielded neither bytes nor a
            // FIN: the peer reset it (RESET_STREAM), or its receive side was
            // otherwise torn down / is gone. Reclaim any tracked state so an
            // abandoned or reset request stream cannot leak an entry in `reqs`.
            if self.reqs.remove(&id).is_some() {
                // Abort our response half if we'd begun one — the request is dead.
                let _ = quic.reset(StreamId(id), H3_REQUEST_INCOMPLETE);
            }
            return;
        }
        // Bound the number of concurrent request streams. A new stream beyond
        // the cap is refused (reset + stop-sending) without allocating state;
        // streams already tracked continue to make progress.
        if !self.reqs.contains_key(&id) && self.reqs.len() >= MAX_REQ_STREAMS {
            let _ = quic.stop_sending(StreamId(id), H3_REQUEST_INCOMPLETE);
            let _ = quic.reset(StreamId(id), H3_REQUEST_INCOMPLETE);
            return;
        }
        let over = {
            let r = self.reqs.entry(id).or_default();
            r.inbuf.extend_from_slice(&data);
            if fin {
                r.fin = true;
            }
            r.inbuf.len() > self.limits.max_body_bytes + self.limits.max_header_bytes
        };
        if over {
            let _ = quic.reset(StreamId(id), H3_REQUEST_INCOMPLETE);
            self.reqs.remove(&id);
        }
    }

    fn handle_request(&mut self, quic: &mut QuicConnection, id: u64, cfg: &SessionConfig) {
        let buf = std::mem::take(&mut self.reqs.get_mut(&id).unwrap().inbuf);
        let req = match self.parse_request(&buf) {
            Ok(req) => req,
            Err(()) => {
                let _ = quic.reset(StreamId(id), H3_MESSAGE_ERROR);
                self.reqs.remove(&id);
                return;
            }
        };

        let resp = cfg.handler.handle(&req);
        #[cfg(feature = "compress")]
        let resp = compress::compress_response(&req, resp, &cfg.compression);
        // HTTP/3 is always over QUIC's TLS 1.3 — secure by definition.
        let resp = crate::session::apply_edge_headers(cfg, resp, true);

        let (bytes, body) = self.encode_response(resp);
        let r = self.reqs.get_mut(&id).unwrap();
        r.delivered = true;
        r.out = bytes;
        r.body = Some(body);
        r.finish_after = true;
    }

    /// Parse the HTTP/3 frames of a complete request stream into a [`Request`].
    fn parse_request(&mut self, buf: &[u8]) -> std::result::Result<Request, ()> {
        let mut pos = 0;
        let mut header_block: Option<Vec<u8>> = None;
        let mut body = Vec::new();
        while pos < buf.len() {
            let (ty, p1) = read_varint(buf, pos).ok_or(())?;
            let (len, p2) = read_varint(buf, p1).ok_or(())?;
            let end = p2.checked_add(len as usize).ok_or(())?;
            if end > buf.len() {
                return Err(()); // truncated frame on a finished stream
            }
            let payload = &buf[p2..end];
            match ty {
                FRAME_HEADERS => {
                    if header_block.is_none() {
                        header_block = Some(payload.to_vec());
                    }
                }
                FRAME_DATA => body.extend_from_slice(payload),
                _ => {} // ignore unknown/reserved frames
            }
            pos = end;
        }

        let block = header_block.ok_or(())?;
        let fields = self
            .qpack_dec
            .decode_field_section(&block)
            .map_err(|_| ())?;
        let head = request_head(
            fields
                .iter()
                .map(|f| (f.name.as_slice(), f.value.as_slice())),
        )?;
        Ok(Request::new(
            head.method,
            head.target,
            Version::Http3,
            head.headers,
            body,
        ))
    }

    /// Encode a response into its HEADERS frame plus the send-side body to frame
    /// as DATA incrementally (so a file body is never read whole here).
    fn encode_response(&mut self, resp: Response) -> (Vec<u8>, OutBody) {
        let (status, headers, body) = resp.into_parts();
        let fields: Vec<HeaderField> =
            response_fields(status, &headers, self.server_name.as_deref())
                .iter()
                .map(|(n, v)| HeaderField::new(n, v))
                .collect();
        let section = self.qpack_enc.encode_field_section(&fields);

        let mut out = Vec::new();
        write_frame(&mut out, FRAME_HEADERS, &section);
        (out, OutBody::from_body(body))
    }

    /// Write pending response bytes for every stream, honoring flow control,
    /// framing the next body chunk as send capacity opens, and FIN-ing streams
    /// whose response is fully sent.
    fn flush(&mut self, quic: &mut QuicConnection) -> Result<()> {
        let mut done = Vec::new();
        for (&id, r) in self.reqs.iter_mut() {
            // Drain already-framed bytes, then frame the next body chunk and keep
            // going until QUIC flow control closes (a short/zero write) or the
            // body is exhausted. A read error mid-stream resets the stream.
            let mut aborted = false;
            loop {
                if r.out_pos < r.out.len() {
                    match quic.write(StreamId(id), &r.out[r.out_pos..]) {
                        Ok(n) => r.out_pos += n,
                        Err(_) => break, // flow control closed; retry next drive
                    }
                    if r.out_pos < r.out.len() {
                        break; // partial write: stream send window is full
                    }
                }
                // Buffer fully written; recycle it and frame the next chunk.
                r.out.clear();
                r.out_pos = 0;
                match &mut r.body {
                    Some(b) if b.remaining() > 0 => {
                        let n = (b.remaining() as usize).min(H3_STREAM_CHUNK);
                        match b.take_chunk(n) {
                            Ok(chunk) => write_frame(&mut r.out, FRAME_DATA, &chunk),
                            Err(()) => {
                                let _ = quic.reset(StreamId(id), H3_REQUEST_INCOMPLETE);
                                done.push(id);
                                aborted = true;
                                break;
                            }
                        }
                    }
                    _ => break, // no more body to frame
                }
            }
            if aborted {
                continue;
            }
            let body_done = r.body.as_ref().is_none_or(|b| b.remaining() == 0);
            if r.finish_after
                && r.out_pos >= r.out.len()
                && body_done
                && !r.finished
                && quic.finish(StreamId(id)).is_ok()
            {
                r.finished = true;
                done.push(id);
            }
        }
        for id in done {
            self.reqs.remove(&id);
        }
        Ok(())
    }
}

fn qerr<E: std::fmt::Debug>(e: E) -> crate::error::Error {
    crate::error::Error::Tls(format!("quic: {e:?}"))
}

/// Read all currently available bytes from a QUIC stream. Returns the bytes and
/// whether FIN has been observed.
fn read_stream(quic: &mut QuicConnection, id: u64) -> (Vec<u8>, bool) {
    let mut data = Vec::new();
    let mut fin = false;
    let mut buf = [0u8; 8192];
    loop {
        match quic.read(StreamId(id), &mut buf) {
            Ok((0, f)) => {
                fin = f;
                break;
            }
            Ok((n, f)) => {
                data.extend_from_slice(&buf[..n]);
                if f {
                    fin = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (data, fin)
}

/// Read and discard a unidirectional stream (we don't act on the peer's control
/// or QPACK streams, having advertised a zero-capacity dynamic table).
fn drain_stream(quic: &mut QuicConnection, id: u64) {
    let _ = read_stream(quic, id);
}

/// Write `data` to a stream, ignoring a short write (the caller's streams are
/// small control messages well within the initial flow-control window).
fn write_all(quic: &mut QuicConnection, id: StreamId, data: &[u8]) -> Result<()> {
    let mut pos = 0;
    while pos < data.len() {
        match quic.write(id, &data[pos..]) {
            Ok(0) => break,
            Ok(n) => pos += n,
            Err(e) => return Err(qerr(e)),
        }
    }
    Ok(())
}

/// Append an HTTP/3 frame (`type`, `length`, payload — all varint-framed).
fn write_frame(out: &mut Vec<u8>, ty: u64, payload: &[u8]) {
    write_varint(out, ty);
    write_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// Encode a QUIC variable-length integer (RFC 9000 §16).
fn write_varint(out: &mut Vec<u8>, v: u64) {
    if v < 1 << 6 {
        out.push(v as u8);
    } else if v < 1 << 14 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

/// Decode a QUIC variable-length integer, returning `(value, next_pos)`.
fn read_varint(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    let first = *buf.get(pos)?;
    let len = 1usize << (first >> 6); // 1, 2, 4, or 8
    if pos + len > buf.len() {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for &b in &buf[pos + 1..pos + len] {
        v = (v << 8) | b as u64;
    }
    Some((v, pos + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        // QUIC varints encode values in [0, 2^62 - 1].
        for v in [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            1 << 29,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut out = Vec::new();
            write_varint(&mut out, v);
            let (got, n) = read_varint(&out, 0).unwrap();
            assert_eq!(got, v);
            assert_eq!(n, out.len());
        }
    }

    #[test]
    fn frame_round_trip() {
        let mut out = Vec::new();
        write_frame(&mut out, FRAME_HEADERS, b"abc");
        let (ty, p1) = read_varint(&out, 0).unwrap();
        let (len, p2) = read_varint(&out, p1).unwrap();
        assert_eq!(ty, FRAME_HEADERS);
        assert_eq!(len, 3);
        assert_eq!(&out[p2..], b"abc");
    }
}
