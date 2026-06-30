//! The sans-I/O HTTP/2 connection engine (server side, RFC 9113).
//!
//! Like [`H1Conn`](crate::proto::H1Conn) it owns no socket: feed it the
//! plaintext bytes that arrive on the (ALPN-negotiated `h2`) TLS connection,
//! drain requests as their streams complete, hand back responses, and write out
//! the serialized frames. Unlike HTTP/1, many requests are multiplexed over one
//! connection, so requests and responses carry a stream id.

use std::collections::BTreeMap;

use compcol::hpack::{DEFAULT_TABLE_SIZE, HeaderField, HpackDecoder, HpackEncoder};

use super::frame::{self, CLIENT_PREFACE, FrameHeader, errcode, flag, ftype, settings};
use crate::proto::{
    Body, Headers, Limits, Method, OutBody, Request, RequestHead, Response, StatusCode, Version,
    request_head,
};

const DEFAULT_WINDOW: i64 = 65_535;
const DEFAULT_MAX_FRAME: usize = 16_384;
/// The receive window we advertise per stream and bump the connection to.
const OUR_WINDOW: u32 = 1 << 20;
/// The largest frame we are willing to accept (also advertised).
const OUR_MAX_FRAME: usize = 1 << 20;
/// MAX_CONCURRENT_STREAMS we advertise and enforce on peer-initiated streams
/// (RFC 9113 §5.1.2). Must match the value sent in our initial SETTINGS.
const MAX_CONCURRENT_STREAMS: u32 = 128;
/// Hard cap on CONTINUATION frames per header block (CONTINUATION-flood guard,
/// CVE-2024-27316 class). Legitimate clients need only a handful.
const MAX_CONTINUATION_FRAMES: u32 = 16;
/// Largest HPACK dynamic table size we let the peer make us keep, regardless of
/// the (up to 2^32-1) value it advertises.
const MAX_HPACK_TABLE_SIZE: usize = 64 * 1024;
/// Rapid-reset (CVE-2023-44487) heuristic: only start scrutinizing the
/// reset:completed ratio once the peer has reset at least this many streams.
const RST_FLOOD_MIN: u64 = 100;
/// The largest receive flow-control window value permitted (RFC 9113 §6.9.1).
const MAX_WINDOW: i64 = 0x7fff_ffff;

/// Per-stream state: request assembly on the recv side, response framing on the
/// send side.
struct Stream {
    // --- receive / request assembly ---
    header_block: Vec<u8>,
    assembling: bool,
    /// Set when the stream was accepted only to keep the HPACK decoder in sync
    /// (it exceeded MAX_CONCURRENT_STREAMS); it is RST_STREAM'd, never delivered.
    refused: bool,
    body: Vec<u8>,
    end_stream_recv: bool,
    delivered: bool,
    /// Whether the delivered request used the HEAD method (response must carry
    /// the headers it would for GET, including Content-Length, but no body).
    is_head: bool,
    // --- send / response framing ---
    send_window: i64,
    out_headers: Vec<u8>,
    out_headers_sent: bool,
    /// The response body still to send (bytes or a file region streamed on
    /// demand), or `None` until a response is set.
    out_body: Option<OutBody>,
    out_end_stream: bool,
    responded: bool,
    done_sending: bool,
}

impl Stream {
    fn new(send_window: i64) -> Stream {
        Stream {
            header_block: Vec::new(),
            assembling: false,
            refused: false,
            body: Vec::new(),
            end_stream_recv: false,
            delivered: false,
            is_head: false,
            send_window,
            out_headers: Vec::new(),
            out_headers_sent: false,
            out_body: None,
            out_end_stream: false,
            responded: false,
            done_sending: false,
        }
    }

    fn out_body_remaining(&self) -> u64 {
        self.out_body.as_ref().map_or(0, |b| b.remaining())
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
    // CONTINUATION frames seen for the header block currently being assembled.
    continuation_frames: u32,
    // Current HPACK encoder dynamic-table size (to skip redundant rebuilds).
    enc_table_size: usize,

    // Rapid-reset (CVE-2023-44487) accounting.
    peer_resets: u64,
    completed: u64,

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
            continuation_frames: 0,
            enc_table_size: DEFAULT_TABLE_SIZE,
            peer_resets: 0,
            completed: 0,
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

    /// Whether there are serialized frames waiting to be written. Body that is
    /// blocked on a closed flow-control window is not "output" yet — it resumes
    /// (via [`pump_out`](Self::pump_out)) when a WINDOW_UPDATE reopens the window.
    pub fn has_output(&self) -> bool {
        !self.outbuf.is_empty()
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
                (settings::MAX_CONCURRENT_STREAMS, MAX_CONCURRENT_STREAMS),
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
                    if self.streams.remove(&header.stream_id).is_some() {
                        self.pending_heads.remove(&header.stream_id);
                        self.peer_resets += 1;
                        // Rapid Reset (CVE-2023-44487): a peer that opens streams
                        // and immediately resets them does cheap-for-it,
                        // expensive-for-us work. Once resets dominate completed
                        // requests, tear the connection down.
                        if self.peer_resets > RST_FLOOD_MIN && self.peer_resets > 2 * self.completed
                        {
                            self.conn_error(errcode::ENHANCE_YOUR_CALM);
                            return;
                        }
                    }
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
                    // Bound our encoder's dynamic table to what the peer allows,
                    // but clamp the (up to 2^32-1) value to a sane maximum and
                    // skip the rebuild when the size is unchanged.
                    let want = (value as usize).min(MAX_HPACK_TABLE_SIZE);
                    if want != self.enc_table_size {
                        self.enc_table_size = want;
                        self.hpack_enc = HpackEncoder::with_max_table_size(want);
                    }
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
            // A window that overflows 2^31-1 is a connection-level
            // FLOW_CONTROL_ERROR (RFC 9113 §6.9.1).
            if self.conn_send_window > MAX_WINDOW {
                self.conn_error(errcode::FLOW_CONTROL_ERROR);
            }
        } else if let Some(s) = self.streams.get_mut(&header.stream_id) {
            s.send_window += inc;
            // Overflow on a stream window is a stream-level FLOW_CONTROL_ERROR.
            if s.send_window > MAX_WINDOW {
                frame::write_rst_stream(
                    &mut self.outbuf,
                    header.stream_id,
                    errcode::FLOW_CONTROL_ERROR,
                );
                self.streams.remove(&header.stream_id);
                self.pending_heads.remove(&header.stream_id);
            }
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
            // Enforce MAX_CONCURRENT_STREAMS (RFC 9113 §5.1.2). We still accept
            // the stream so its header block can be fed to the HPACK decoder
            // (skipping it would desync the connection's compression state), but
            // mark it `refused`: it is RST_STREAM'd and never delivered.
            let over_cap = self.streams.len() as u32 >= MAX_CONCURRENT_STREAMS;
            let w = self.peer_initial_window;
            let mut stream = Stream::new(w);
            stream.refused = over_cap;
            self.streams.insert(sid, stream);
        }

        // A HEADERS frame always begins a new header block, so reset the
        // per-block CONTINUATION counter here.
        self.continuation_frames = 0;

        let end_stream = header.has(flag::END_STREAM);
        let end_headers = header.has(flag::END_HEADERS);
        let too_big = {
            let s = self.streams.get_mut(&sid).unwrap();
            s.header_block.extend_from_slice(block);
            s.assembling = true;
            if end_stream {
                s.end_stream_recv = true;
            }
            s.header_block.len() > self.limits.max_header_bytes
        };
        // Header-bomb guard (CVE-2024-27316 class): HPACK only runs at
        // END_HEADERS, so bound the accumulated block before then.
        if too_big {
            self.conn_error(errcode::ENHANCE_YOUR_CALM);
            return;
        }
        if end_headers {
            self.finish_headers(sid);
        } else {
            self.continuation_stream = Some(sid);
        }
    }

    fn on_continuation(&mut self, header: &FrameHeader, payload: &[u8]) {
        let sid = header.stream_id;
        // CONTINUATION-flood guard (CVE-2024-27316 class): cap how many
        // CONTINUATION frames a single header block may span.
        self.continuation_frames += 1;
        if self.continuation_frames > MAX_CONTINUATION_FRAMES {
            self.conn_error(errcode::ENHANCE_YOUR_CALM);
            return;
        }
        let limit = self.limits.max_header_bytes;
        let too_big = match self.streams.get_mut(&sid) {
            Some(s) if s.assembling => {
                s.header_block.extend_from_slice(payload);
                s.header_block.len() > limit
            }
            // Unknown stream, or a CONTINUATION not preceded by an open HEADERS.
            _ => {
                self.conn_error(errcode::PROTOCOL_ERROR);
                return;
            }
        };
        if too_big {
            self.conn_error(errcode::ENHANCE_YOUR_CALM);
            return;
        }
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

        // Over the concurrency cap: the block has now been decoded (HPACK stays
        // in sync), so refuse the stream without delivering it.
        if self.streams.get(&sid).is_some_and(|s| s.refused) {
            frame::write_rst_stream(&mut self.outbuf, sid, errcode::REFUSED_STREAM);
            self.streams.remove(&sid);
            self.pending_heads.remove(&sid);
            return;
        }

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
        // Whole DATA frame (including padding) counts against flow control.
        let counted = payload.len() as u32;

        let over_limit = match self.streams.get_mut(&sid) {
            Some(s) => {
                s.body.extend_from_slice(content);
                if header.has(flag::END_STREAM) {
                    s.end_stream_recv = true;
                }
                s.body.len() > self.limits.max_body_bytes
            }
            // Unknown/closed stream: do NOT reflect WINDOW_UPDATEs back, or DATA
            // on a nonexistent stream would elicit free window credit.
            None => return,
        };

        if over_limit {
            frame::write_rst_stream(&mut self.outbuf, sid, errcode::ENHANCE_YOUR_CALM);
            self.streams.remove(&sid);
            self.pending_heads.remove(&sid);
            // Return the octets to the connection window only (the stream is
            // gone) so connection-level flow control stays consistent.
            if counted > 0 {
                frame::write_window_update(&mut self.outbuf, 0, counted);
            }
            return;
        }

        // The stream accepted the data; replenish both windows now (we buffer
        // immediately, so the credit can be returned).
        if counted > 0 {
            frame::write_window_update(&mut self.outbuf, 0, counted);
            frame::write_window_update(&mut self.outbuf, sid, counted);
        }

        if header.has(flag::END_STREAM)
            && let Some(parts) = self.pending_heads.remove(&sid)
        {
            let body = std::mem::take(&mut self.streams.get_mut(&sid).unwrap().body);
            self.deliver(sid, parts, body);
        }
    }

    fn deliver(&mut self, sid: u32, head: RequestHead, body: Vec<u8>) {
        let is_head = head.method == Method::Head;
        if let Some(s) = self.streams.get_mut(&sid) {
            s.delivered = true;
            s.is_head = is_head;
        }
        self.completed += 1;
        let req = Request::new(head.method, head.target, Version::Http2, head.headers, body);
        self.ready.push_back((sid, req));
        // The ready queue can only outgrow the concurrency cap if the
        // application is not draining it; refuse to buffer without bound.
        if self.ready.len() > MAX_CONCURRENT_STREAMS as usize {
            self.conn_error(errcode::ENHANCE_YOUR_CALM);
        }
    }

    /// Serialize a response for `sid`: a HEADERS frame followed by flow-control
    /// limited DATA frames.
    pub fn respond(&mut self, sid: u32, resp: Response) {
        let Some(s0) = self.streams.get(&sid) else {
            return; // stream was reset/closed
        };
        let is_head = s0.is_head;
        let (status, mut headers, body) = resp.into_parts();
        // A HEAD response carries the same headers a GET would — including the
        // entity Content-Length — but no body. Report the length, then drop it
        // so the file is never streamed in answer to a HEAD.
        let body = if is_head {
            if !status.is_bodyless() {
                headers.set_if_absent("content-length", body.len().to_string());
            }
            Body::empty()
        } else {
            body
        };
        let fields = response_fields(status, &headers, self.server_name.as_deref());
        let encoded = self.hpack_enc.encode(&fields);

        {
            let s = self.streams.get_mut(&sid).unwrap();
            s.out_headers = encoded;
            s.out_body = Some(OutBody::from_body(body));
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
        // Streams whose body read failed mid-stream: reset rather than send a
        // truncated, mis-framed body (never panic).
        let mut reset = Vec::new();
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
                    // The chunk is bounded by the available send window (and max
                    // frame), so a file body is read in window-sized pieces — the
                    // whole file is never pulled into memory at once.
                    let n = remaining.min(budget as u64) as usize;
                    (n, s.out_end_stream && (n as u64) == remaining)
                };

                let payload = {
                    let s = self.streams.get_mut(&sid).unwrap();
                    match s.out_body.as_mut().unwrap().take_chunk(chunk_len) {
                        Ok(p) => p,
                        Err(()) => {
                            reset.push(sid);
                            break;
                        }
                    }
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
        // Abort streams whose body could not be read.
        for sid in reset {
            frame::write_rst_stream(&mut self.outbuf, sid, errcode::INTERNAL_ERROR);
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
    fn head_response_has_length_but_no_body() {
        let mut c = H2Conn::new(Limits::default(), Some("httpsd".into()));
        let mut enc = HpackEncoder::new();
        let mut wire = Vec::new();
        wire.extend_from_slice(CLIENT_PREFACE);
        frame::write_settings(&mut wire, &[]);
        wire.extend_from_slice(&client_request(
            &mut enc,
            1,
            &[
                HeaderField::new(b":method", b"HEAD"),
                HeaderField::new(b":scheme", b"https"),
                HeaderField::new(b":authority", b"a"),
                HeaderField::new(b":path", b"/file"),
            ],
            None,
        ));
        c.received(&wire);
        let (sid, req) = c.poll_request().expect("request");
        assert_eq!(req.method(), &Method::Head);

        // Respond as a handler would for the matching GET: a non-empty body.
        c.respond(sid, Response::text("the full body bytes"));
        let out = c.take_out();
        let (hblock, data) = collect(&out, 1);
        // No DATA frames at all for a HEAD response...
        assert!(data.is_empty(), "HEAD must not send a body");
        // ...but the entity Content-Length is still advertised.
        let fields = HpackDecoder::new().decode(&hblock).expect("decode");
        let clen = fields
            .iter()
            .find(|f| f.name == b"content-length")
            .expect("content-length present on HEAD");
        assert_eq!(clen.value, b"19"); // len("the full body bytes")
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

    /// Return the error code of the first frame of `ty` for `sid` (last 4 bytes
    /// of its payload), if any. Works for GOAWAY (sid 0) and RST_STREAM.
    fn frame_code(out: &[u8], ty: u8, sid: u32) -> Option<u32> {
        let mut pos = 0;
        while pos + 9 <= out.len() {
            let h = FrameHeader::parse(&out[pos..pos + 9]);
            let body = &out[pos + 9..pos + 9 + h.length];
            if h.ftype == ty && h.stream_id == sid && body.len() >= 4 {
                let n = body.len();
                return Some(u32::from_be_bytes([
                    body[n - 4],
                    body[n - 3],
                    body[n - 2],
                    body[n - 1],
                ]));
            }
            pos += 9 + h.length;
        }
        None
    }

    #[test]
    fn oversized_header_block_is_rejected() {
        let limits = Limits {
            max_header_bytes: 1024,
            max_body_bytes: 1 << 20,
        };
        let mut c = H2Conn::new(limits, None);
        let mut wire = Vec::new();
        wire.extend_from_slice(CLIENT_PREFACE);
        frame::write_settings(&mut wire, &[]);
        // A HEADERS frame without END_HEADERS whose block already exceeds the
        // limit: the cap must fire before HPACK ever runs.
        let big = vec![0u8; 2048];
        frame::write_frame(&mut wire, ftype::HEADERS, 0, 1, &big);
        c.received(&wire);
        assert!(c.wants_close());
        assert_eq!(
            frame_code(&c.take_out(), ftype::GOAWAY, 0),
            Some(errcode::ENHANCE_YOUR_CALM)
        );
    }

    #[test]
    fn continuation_flood_is_rejected() {
        let mut c = H2Conn::new(Limits::default(), None);
        let mut wire = Vec::new();
        wire.extend_from_slice(CLIENT_PREFACE);
        frame::write_settings(&mut wire, &[]);
        // Open a header block and never end it, flooding CONTINUATIONs.
        frame::write_frame(&mut wire, ftype::HEADERS, 0, 1, &[]);
        for _ in 0..(MAX_CONTINUATION_FRAMES + 1) {
            frame::write_frame(&mut wire, ftype::CONTINUATION, 0, 1, &[]);
        }
        c.received(&wire);
        assert!(c.wants_close());
        assert_eq!(
            frame_code(&c.take_out(), ftype::GOAWAY, 0),
            Some(errcode::ENHANCE_YOUR_CALM)
        );
    }

    #[test]
    fn concurrent_stream_cap_refuses_excess() {
        let mut c = H2Conn::new(Limits::default(), None);
        let mut enc = HpackEncoder::new();
        let mut wire = Vec::new();
        wire.extend_from_slice(CLIENT_PREFACE);
        frame::write_settings(&mut wire, &[]);
        let req_fields = |path: &'static [u8]| {
            vec![
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":scheme", b"https"),
                HeaderField::new(b":authority", b"a"),
                HeaderField::new(b":path", path),
            ]
        };
        // Open exactly MAX_CONCURRENT_STREAMS streams; they stay open awaiting a
        // response, so they all count against the cap.
        for i in 0..MAX_CONCURRENT_STREAMS {
            let sid = 1 + 2 * i;
            wire.extend_from_slice(&client_request(&mut enc, sid, &req_fields(b"/"), None));
        }
        // One more must be refused without closing the connection.
        let extra = 1 + 2 * MAX_CONCURRENT_STREAMS;
        wire.extend_from_slice(&client_request(&mut enc, extra, &req_fields(b"/x"), None));
        c.received(&wire);

        assert!(!c.wants_close(), "stream cap must not kill the connection");
        let mut delivered = 0;
        while c.poll_request().is_some() {
            delivered += 1;
        }
        assert_eq!(delivered, MAX_CONCURRENT_STREAMS as usize);
        assert_eq!(
            frame_code(&c.take_out(), ftype::RST_STREAM, extra),
            Some(errcode::REFUSED_STREAM)
        );
    }

    #[test]
    fn file_body_streams_under_flow_control() {
        use std::io::Write;
        use std::sync::Arc;

        use crate::proto::Body;

        // A file body larger than the initial 65535-byte send window, so it can
        // only finish once the peer opens the window with WINDOW_UPDATEs — proof
        // we stream incrementally rather than dumping the whole file.
        let total = 200_000usize;
        let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let path = std::env::temp_dir().join(format!("httpsd-h2-stream-{}", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&data).unwrap();
            f.sync_all().unwrap();
        }
        let file = Arc::new(std::fs::File::open(&path).unwrap());
        let _ = std::fs::remove_file(&path);

        let mut c = H2Conn::new(Limits::default(), None);
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
                HeaderField::new(b":authority", b"a"),
                HeaderField::new(b":path", b"/big"),
            ],
            None,
        ));
        c.received(&wire);
        let (sid, _req) = c.poll_request().expect("request");
        c.respond(
            sid,
            Response::new(StatusCode::OK).body(Body::file(file, 0, total as u64)),
        );

        // First burst is bounded by the initial connection/stream window.
        let mut body = Vec::new();
        let (_h, d) = collect(&c.take_out(), 1);
        body.extend_from_slice(&d);
        assert!(
            body.len() < total,
            "initial window must NOT let the whole file out: got {}",
            body.len()
        );

        // Open both windows generously and keep pumping until the body is done.
        for _ in 0..64 {
            if body.len() >= total {
                break;
            }
            let mut wu = Vec::new();
            frame::write_window_update(&mut wu, 0, 1 << 20);
            frame::write_window_update(&mut wu, 1, 1 << 20);
            c.received(&wu);
            let (_h, d) = collect(&c.take_out(), 1);
            body.extend_from_slice(&d);
        }
        assert_eq!(body.len(), total, "whole file must eventually stream out");
        assert_eq!(body, data, "streamed body must be byte-exact");
    }

    #[test]
    fn window_update_overflow_is_flow_control_error() {
        let mut c = H2Conn::new(Limits::default(), None);
        let mut wire = Vec::new();
        wire.extend_from_slice(CLIENT_PREFACE);
        frame::write_settings(&mut wire, &[]);
        // A connection-level WINDOW_UPDATE that pushes the window past 2^31-1.
        frame::write_window_update(&mut wire, 0, 0x7fff_ffff);
        c.received(&wire);
        assert!(c.wants_close());
        assert_eq!(
            frame_code(&c.take_out(), ftype::GOAWAY, 0),
            Some(errcode::FLOW_CONTROL_ERROR)
        );
    }
}
