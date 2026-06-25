//! The sans-I/O HTTP/2 connection engine (server side, RFC 9113).
//!
//! Like [`H1Conn`](crate::proto::H1Conn) it owns no socket: feed it the
//! plaintext bytes that arrive on the (ALPN-negotiated `h2`) TLS connection,
//! drain requests as their streams complete, hand back responses, and write out
//! the serialized frames. Unlike HTTP/1, many requests are multiplexed over one
//! connection, so requests and responses carry a stream id.

use std::collections::BTreeMap;

use compcol::hpack::{HeaderField, HpackDecoder, HpackEncoder};

use super::frame::{self, CLIENT_PREFACE, FrameHeader, errcode, flag, ftype, settings};
use crate::proto::{
    Headers, Limits, Request, RequestHead, Response, StatusCode, Version, request_head,
};

const DEFAULT_WINDOW: i64 = 65_535;
const DEFAULT_MAX_FRAME: usize = 16_384;
/// The receive window we advertise per stream and bump the connection to.
const OUR_WINDOW: u32 = 1 << 20;
/// The largest frame we are willing to accept (also advertised).
const OUR_MAX_FRAME: usize = 1 << 20;

/// Per-stream state: request assembly on the recv side, response framing on the
/// send side.
struct Stream {
    // --- receive / request assembly ---
    header_block: Vec<u8>,
    assembling: bool,
    body: Vec<u8>,
    end_stream_recv: bool,
    delivered: bool,
    // --- send / response framing ---
    send_window: i64,
    out_headers: Vec<u8>,
    out_headers_sent: bool,
    out_body: Vec<u8>,
    out_body_pos: usize,
    out_end_stream: bool,
    responded: bool,
    done_sending: bool,
}

impl Stream {
    fn new(send_window: i64) -> Stream {
        Stream {
            header_block: Vec::new(),
            assembling: false,
            body: Vec::new(),
            end_stream_recv: false,
            delivered: false,
            send_window,
            out_headers: Vec::new(),
            out_headers_sent: false,
            out_body: Vec::new(),
            out_body_pos: 0,
            out_end_stream: false,
            responded: false,
            done_sending: false,
        }
    }

    fn out_body_remaining(&self) -> usize {
        self.out_body.len() - self.out_body_pos
    }
}

/// A sans-I/O HTTP/2 server connection.
pub struct H2Conn {
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    limits: Limits,
    server_name: Option<String>,

    hpack_dec: HpackDecoder,
    hpack_enc: HpackEncoder,

    preface_seen: bool,
    our_settings_sent: bool,

    // Peer settings that govern how we send.
    peer_initial_window: i64,
    peer_max_frame: usize,

    // Send-side flow control.
    conn_send_window: i64,

    // Header (de)assembly continuation target.
    continuation_stream: Option<u32>,

    streams: BTreeMap<u32, Stream>,
    last_peer_stream: u32,
    ready: std::collections::VecDeque<(u32, Request)>,
    /// Decoded request heads for streams whose body is still arriving (kept off
    /// `Stream` to avoid borrow conflicts inside the frame loop).
    pending_heads: BTreeMap<u32, RequestHead>,

    goaway_sent: bool,
    closed: bool,
}

impl H2Conn {
    /// Create a new HTTP/2 server engine.
    pub fn new(limits: Limits, server_name: Option<String>) -> H2Conn {
        H2Conn {
            inbuf: Vec::new(),
            outbuf: Vec::new(),
            limits,
            server_name,
            hpack_dec: HpackDecoder::new(),
            hpack_enc: HpackEncoder::new(),
            preface_seen: false,
            our_settings_sent: false,
            peer_initial_window: DEFAULT_WINDOW,
            peer_max_frame: DEFAULT_MAX_FRAME,
            conn_send_window: DEFAULT_WINDOW,
            continuation_stream: None,
            streams: BTreeMap::new(),
            last_peer_stream: 0,
            ready: std::collections::VecDeque::new(),
            pending_heads: BTreeMap::new(),
            goaway_sent: false,
            closed: false,
        }
    }

    /// Drain and return all serialized frames queued so far.
    pub fn take_out(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbuf)
    }

    /// Whether the connection should close once output is flushed.
    pub fn wants_close(&self) -> bool {
        self.closed
    }

    /// Pop the next fully-received request, with its stream id.
    pub fn poll_request(&mut self) -> Option<(u32, Request)> {
        self.ready.pop_front()
    }

    /// Feed plaintext bytes, parsing frames and assembling requests.
    pub fn received(&mut self, data: &[u8]) {
        if self.closed {
            return;
        }
        self.inbuf.extend_from_slice(data);

        if !self.preface_seen {
            if self.inbuf.len() < CLIENT_PREFACE.len() {
                return;
            }
            if &self.inbuf[..CLIENT_PREFACE.len()] != CLIENT_PREFACE {
                self.conn_error(errcode::PROTOCOL_ERROR);
                return;
            }
            self.inbuf.drain(..CLIENT_PREFACE.len());
            self.preface_seen = true;
            self.send_initial_settings();
        }

        self.parse_frames();
        self.pump_out();
    }

    fn send_initial_settings(&mut self) {
        frame::write_settings(
            &mut self.outbuf,
            &[
                (settings::ENABLE_PUSH, 0),
                (settings::MAX_CONCURRENT_STREAMS, 128),
                (settings::INITIAL_WINDOW_SIZE, OUR_WINDOW),
                (settings::MAX_FRAME_SIZE, OUR_MAX_FRAME as u32),
            ],
        );
        // Raise the connection-level receive window from the 65535 default.
        frame::write_window_update(&mut self.outbuf, 0, OUR_WINDOW - DEFAULT_WINDOW as u32);
        self.our_settings_sent = true;
    }

    fn parse_frames(&mut self) {
        while !self.closed && self.inbuf.len() >= 9 {
            let header = FrameHeader::parse(&self.inbuf[..9]);
            if header.length > OUR_MAX_FRAME {
                self.conn_error(errcode::FRAME_SIZE_ERROR);
                return;
            }
            if self.inbuf.len() < 9 + header.length {
                return; // wait for the full frame
            }
            let payload = self.inbuf[9..9 + header.length].to_vec();
            self.inbuf.drain(..9 + header.length);

            // A CONTINUATION must immediately follow its HEADERS on the same stream.
            if let Some(cs) = self.continuation_stream
                && (header.ftype != ftype::CONTINUATION || header.stream_id != cs)
            {
                self.conn_error(errcode::PROTOCOL_ERROR);
                return;
            }

            match header.ftype {
                ftype::SETTINGS => self.on_settings(&header, &payload),
                ftype::WINDOW_UPDATE => self.on_window_update(&header, &payload),
                ftype::PING => self.on_ping(&header, &payload),
                ftype::HEADERS => self.on_headers(&header, &payload),
                ftype::CONTINUATION => self.on_continuation(&header, &payload),
                ftype::DATA => self.on_data(&header, &payload),
                ftype::RST_STREAM => {
                    self.streams.remove(&header.stream_id);
                }
                ftype::GOAWAY => {
                    // Peer is shutting down; finish in-flight work, then close.
                    self.closed = true;
                }
                // PRIORITY, PUSH_PROMISE (server never receives), and unknown
                // types are ignored per RFC 9113 §4.1 / §5.5.
                _ => {}
            }
        }
    }

    fn on_settings(&mut self, header: &FrameHeader, payload: &[u8]) {
        if header.has(flag::ACK) {
            return;
        }
        let Some(params) = frame::parse_settings(payload) else {
            self.conn_error(errcode::FRAME_SIZE_ERROR);
            return;
        };
        for (id, value) in params {
            match id {
                settings::INITIAL_WINDOW_SIZE => {
                    if value > 0x7fff_ffff {
                        self.conn_error(errcode::FLOW_CONTROL_ERROR);
                        return;
                    }
                    let delta = value as i64 - self.peer_initial_window;
                    self.peer_initial_window = value as i64;
                    for s in self.streams.values_mut() {
                        s.send_window += delta;
                    }
                }
                settings::MAX_FRAME_SIZE => {
                    self.peer_max_frame = (value as usize).clamp(DEFAULT_MAX_FRAME, OUR_MAX_FRAME);
                }
                settings::HEADER_TABLE_SIZE => {
                    // Bound our encoder's dynamic table to what the peer allows.
                    self.hpack_enc = HpackEncoder::with_max_table_size(value as usize);
                }
                _ => {}
            }
        }
        frame::write_settings_ack(&mut self.outbuf);
    }

    fn on_window_update(&mut self, header: &FrameHeader, payload: &[u8]) {
        if payload.len() != 4 {
            self.conn_error(errcode::FRAME_SIZE_ERROR);
            return;
        }
        let inc = (u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
            & 0x7fff_ffff) as i64;
        if inc == 0 {
            self.conn_error(errcode::PROTOCOL_ERROR);
            return;
        }
        if header.stream_id == 0 {
            self.conn_send_window += inc;
        } else if let Some(s) = self.streams.get_mut(&header.stream_id) {
            s.send_window += inc;
        }
    }

    fn on_ping(&mut self, header: &FrameHeader, payload: &[u8]) {
        if header.has(flag::ACK) || payload.len() != 8 {
            return;
        }
        frame::write_frame(&mut self.outbuf, ftype::PING, flag::ACK, 0, payload);
    }

    fn on_headers(&mut self, header: &FrameHeader, payload: &[u8]) {
        let sid = header.stream_id;
        if sid == 0 || sid.is_multiple_of(2) {
            self.conn_error(errcode::PROTOCOL_ERROR);
            return;
        }
        // Strip optional padding, then an optional 5-byte priority prefix.
        let Some(mut block) = frame::strip_padding(payload, header.has(flag::PADDED)) else {
            self.conn_error(errcode::PROTOCOL_ERROR);
            return;
        };
        if header.has(flag::PRIORITY) {
            if block.len() < 5 {
                self.conn_error(errcode::PROTOCOL_ERROR);
                return;
            }
            block = &block[5..];
        }

        if !self.streams.contains_key(&sid) {
            if sid <= self.last_peer_stream {
                self.conn_error(errcode::PROTOCOL_ERROR);
                return;
            }
            self.last_peer_stream = sid;
            let w = self.peer_initial_window;
            self.streams.insert(sid, Stream::new(w));
        }

        let end_stream = header.has(flag::END_STREAM);
        let end_headers = header.has(flag::END_HEADERS);
        {
            let s = self.streams.get_mut(&sid).unwrap();
            s.header_block.extend_from_slice(block);
            s.assembling = true;
            if end_stream {
                s.end_stream_recv = true;
            }
        }
        if end_headers {
            self.finish_headers(sid);
        } else {
            self.continuation_stream = Some(sid);
        }
    }

    fn on_continuation(&mut self, header: &FrameHeader, payload: &[u8]) {
        let sid = header.stream_id;
        let Some(s) = self.streams.get_mut(&sid) else {
            self.conn_error(errcode::PROTOCOL_ERROR);
            return;
        };
        if !s.assembling {
            self.conn_error(errcode::PROTOCOL_ERROR);
            return;
        }
        s.header_block.extend_from_slice(payload);
        if header.has(flag::END_HEADERS) {
            self.continuation_stream = None;
            self.finish_headers(sid);
        }
    }

    /// Decode an assembled header block (HPACK must stay in sync, so this runs
    /// for every completed block) and either deliver the request or, if it
    /// carries a body, leave the stream open for DATA.
    fn finish_headers(&mut self, sid: u32) {
        let block = {
            let s = self.streams.get_mut(&sid).unwrap();
            s.assembling = false;
            std::mem::take(&mut s.header_block)
        };
        let fields = match self.hpack_dec.decode(&block) {
            Ok(f) => f,
            Err(_) => {
                self.conn_error(errcode::COMPRESSION_ERROR);
                return;
            }
        };

        let end_stream = self
            .streams
            .get(&sid)
            .map(|s| s.end_stream_recv)
            .unwrap_or(false);
        let head = request_head(
            fields
                .iter()
                .map(|f| (f.name.as_slice(), f.value.as_slice())),
        );
        match head {
            Ok(parts) => {
                if end_stream {
                    self.deliver(sid, parts, Vec::new());
                } else {
                    // Body to follow; hold the head until END_STREAM on DATA.
                    self.pending_heads.insert(sid, parts);
                }
            }
            Err(()) => {
                // Malformed request → reset just this stream.
                frame::write_rst_stream(&mut self.outbuf, sid, errcode::PROTOCOL_ERROR);
                self.streams.remove(&sid);
                self.pending_heads.remove(&sid);
            }
        }
    }

    fn on_data(&mut self, header: &FrameHeader, payload: &[u8]) {
        let sid = header.stream_id;
        let Some(content) = frame::strip_padding(payload, header.has(flag::PADDED)) else {
            self.conn_error(errcode::PROTOCOL_ERROR);
            return;
        };
        // Whole DATA frame (including padding) counts against flow control;
        // replenish both windows since we buffer immediately.
        let counted = payload.len() as u32;
        if counted > 0 {
            frame::write_window_update(&mut self.outbuf, 0, counted);
            frame::write_window_update(&mut self.outbuf, sid, counted);
        }

        let over_limit = match self.streams.get_mut(&sid) {
            Some(s) => {
                s.body.extend_from_slice(content);
                if header.has(flag::END_STREAM) {
                    s.end_stream_recv = true;
                }
                s.body.len() > self.limits.max_body_bytes
            }
            None => return, // unknown/closed stream
        };

        if over_limit {
            frame::write_rst_stream(&mut self.outbuf, sid, errcode::ENHANCE_YOUR_CALM);
            self.streams.remove(&sid);
            self.pending_heads.remove(&sid);
            return;
        }

        if header.has(flag::END_STREAM)
            && let Some(parts) = self.pending_heads.remove(&sid)
        {
            let body = std::mem::take(&mut self.streams.get_mut(&sid).unwrap().body);
            self.deliver(sid, parts, body);
        }
    }

    fn deliver(&mut self, sid: u32, head: RequestHead, body: Vec<u8>) {
        if let Some(s) = self.streams.get_mut(&sid) {
            s.delivered = true;
        }
        let req = Request::new(head.method, head.target, Version::Http2, head.headers, body);
        self.ready.push_back((sid, req));
    }

    /// Serialize a response for `sid`: a HEADERS frame followed by flow-control
    /// limited DATA frames.
    pub fn respond(&mut self, sid: u32, resp: Response) {
        let Some(_) = self.streams.get(&sid) else {
            return; // stream was reset/closed
        };
        let (status, headers, body) = resp.into_parts();
        let fields = response_fields(status, &headers, self.server_name.as_deref());
        let encoded = self.hpack_enc.encode(&fields);

        {
            let s = self.streams.get_mut(&sid).unwrap();
            s.out_headers = encoded;
            s.out_body = body;
            s.out_end_stream = true;
            s.responded = true;
        }
        self.emit_headers(sid);
        self.pump_out();
    }

    fn emit_headers(&mut self, sid: u32) {
        let (encoded, has_body) = {
            let s = self.streams.get_mut(&sid).unwrap();
            if s.out_headers_sent {
                return;
            }
            s.out_headers_sent = true;
            (
                std::mem::take(&mut s.out_headers),
                s.out_body_remaining() > 0,
            )
        };

        let max = self.peer_max_frame.max(1);
        let end_stream = !has_body;
        let mut chunks = encoded.chunks(max).peekable();
        // A header block that happens to be empty still needs one HEADERS frame.
        if chunks.peek().is_none() {
            let flags = flag::END_HEADERS | if end_stream { flag::END_STREAM } else { 0 };
            frame::write_frame(&mut self.outbuf, ftype::HEADERS, flags, sid, &[]);
            return;
        }
        let mut first = true;
        while let Some(chunk) = chunks.next() {
            let last = chunks.peek().is_none();
            let (ty, mut flags) = if first {
                (ftype::HEADERS, 0u8)
            } else {
                (ftype::CONTINUATION, 0u8)
            };
            if last {
                flags |= flag::END_HEADERS;
                if first && end_stream {
                    flags |= flag::END_STREAM;
                }
            }
            frame::write_frame(&mut self.outbuf, ty, flags, sid, chunk);
            first = false;
        }
    }

    /// Emit as much pending response body as the connection and per-stream
    /// send windows allow.
    pub fn pump_out(&mut self) {
        let mut finished = Vec::new();
        let sids: Vec<u32> = self.streams.keys().copied().collect();
        for sid in sids {
            loop {
                let (chunk_len, end) = {
                    let s = match self.streams.get(&sid) {
                        Some(s) if s.out_headers_sent => s,
                        _ => break,
                    };
                    let remaining = s.out_body_remaining();
                    if remaining == 0 {
                        // Empty body: END_STREAM rode on the HEADERS frame, so
                        // the response is already complete — retire the stream.
                        if s.responded && !s.done_sending {
                            finished.push(sid);
                        }
                        break;
                    }
                    let budget = self
                        .conn_send_window
                        .min(s.send_window)
                        .min(self.peer_max_frame as i64);
                    if budget <= 0 {
                        break;
                    }
                    let n = (remaining as i64).min(budget) as usize;
                    (n, s.out_end_stream && n == remaining)
                };

                let payload = {
                    let s = self.streams.get_mut(&sid).unwrap();
                    let start = s.out_body_pos;
                    s.out_body_pos += chunk_len;
                    s.out_body[start..start + chunk_len].to_vec()
                };
                self.conn_send_window -= chunk_len as i64;
                {
                    let s = self.streams.get_mut(&sid).unwrap();
                    s.send_window -= chunk_len as i64;
                }
                let flags = if end { flag::END_STREAM } else { 0 };
                frame::write_frame(&mut self.outbuf, ftype::DATA, flags, sid, &payload);
                if end {
                    if let Some(s) = self.streams.get_mut(&sid) {
                        s.done_sending = true;
                    }
                    finished.push(sid);
                    break;
                }
            }
        }
        // Drop streams whose response is fully written.
        for sid in finished {
            self.streams.remove(&sid);
            self.pending_heads.remove(&sid);
        }
    }

    fn conn_error(&mut self, code: u32) {
        if !self.goaway_sent {
            frame::write_goaway(&mut self.outbuf, self.last_peer_stream, code);
            self.goaway_sent = true;
        }
        self.closed = true;
    }
}

/// Build the HPACK field list for a response from the shared response-header
/// rules (`:status` first, hop-by-hop dropped, `server` defaulted).
fn response_fields(
    status: StatusCode,
    headers: &Headers,
    server: Option<&str>,
) -> Vec<HeaderField> {
    crate::proto::response_fields(status, headers, server)
        .iter()
        .map(|(n, v)| HeaderField::new(n, v))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Method;

    /// Walk a buffer of frames, returning the concatenated HEADERS blocks and
    /// DATA payloads for `want_stream`.
    fn collect(out: &[u8], want_stream: u32) -> (Vec<u8>, Vec<u8>) {
        let mut pos = 0;
        let (mut headers, mut data) = (Vec::new(), Vec::new());
        while pos + 9 <= out.len() {
            let h = FrameHeader::parse(&out[pos..pos + 9]);
            let body = &out[pos + 9..pos + 9 + h.length];
            if h.stream_id == want_stream {
                match h.ftype {
                    ftype::HEADERS | ftype::CONTINUATION => headers.extend_from_slice(body),
                    ftype::DATA => data.extend_from_slice(body),
                    _ => {}
                }
            }
            pos += 9 + h.length;
        }
        (headers, data)
    }

    fn client_request(
        enc: &mut HpackEncoder,
        sid: u32,
        fields: &[HeaderField],
        body: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        let block = enc.encode(fields);
        let end_stream = body.is_none();
        let flags = flag::END_HEADERS | if end_stream { flag::END_STREAM } else { 0 };
        frame::write_frame(&mut buf, ftype::HEADERS, flags, sid, &block);
        if let Some(b) = body {
            frame::write_frame(&mut buf, ftype::DATA, flag::END_STREAM, sid, b);
        }
        buf
    }

    #[test]
    fn get_request_and_response() {
        let mut c = H2Conn::new(Limits::default(), Some("httpsd".into()));
        let mut enc = HpackEncoder::new();

        let mut wire = Vec::new();
        wire.extend_from_slice(CLIENT_PREFACE);
        frame::write_settings(&mut wire, &[]);
        wire.extend_from_slice(&client_request(
            &mut enc,
            1,
            &[
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":scheme", b"https"),
                HeaderField::new(b":authority", b"example.test"),
                HeaderField::new(b":path", b"/hi?x=1"),
            ],
            None,
        ));

        c.received(&wire);
        let (sid, req) = c.poll_request().expect("request delivered");
        assert_eq!(sid, 1);
        assert_eq!(req.method(), &Method::Get);
        assert_eq!(req.path(), "/hi");
        assert_eq!(req.query(), Some("x=1"));
        assert_eq!(req.host(), Some("example.test"));
        assert_eq!(req.version(), Version::Http2);

        c.respond(1, Response::text("hello h2"));
        let out = c.take_out();
        let (hblock, data) = collect(&out, 1);
        let fields = HpackDecoder::new()
            .decode(&hblock)
            .expect("decode resp headers");
        let status = fields
            .iter()
            .find(|f| f.name == b":status")
            .expect("status");
        assert_eq!(status.value, b"200");
        assert_eq!(data, b"hello h2");
    }

    #[test]
    fn post_with_body_is_buffered() {
        let mut c = H2Conn::new(Limits::default(), None);
        let mut enc = HpackEncoder::new();
        let mut wire = Vec::new();
        wire.extend_from_slice(CLIENT_PREFACE);
        frame::write_settings(&mut wire, &[]);
        wire.extend_from_slice(&client_request(
            &mut enc,
            1,
            &[
                HeaderField::new(b":method", b"POST"),
                HeaderField::new(b":scheme", b"https"),
                HeaderField::new(b":authority", b"a"),
                HeaderField::new(b":path", b"/upload"),
            ],
            Some(b"payload-bytes"),
        ));
        c.received(&wire);
        let (_sid, req) = c.poll_request().expect("request");
        assert_eq!(req.method(), &Method::Post);
        assert_eq!(req.body(), b"payload-bytes");
    }

    #[test]
    fn bad_preface_closes() {
        let mut c = H2Conn::new(Limits::default(), None);
        c.received(b"NOT-A-PREFACE-AT-ALL-XXXX");
        assert!(c.wants_close());
    }
}
