//! HTTP/2 binary framing (RFC 9113 §4–6): the 9-octet frame header, the frame
//! type/flag constants, and a few payload (de)serializers.

/// Frame type codes (RFC 9113 §6).
#[allow(dead_code)] // a complete set of protocol constants
pub mod ftype {
    pub const DATA: u8 = 0x0;
    pub const HEADERS: u8 = 0x1;
    pub const PRIORITY: u8 = 0x2;
    pub const RST_STREAM: u8 = 0x3;
    pub const SETTINGS: u8 = 0x4;
    pub const PUSH_PROMISE: u8 = 0x5;
    pub const PING: u8 = 0x6;
    pub const GOAWAY: u8 = 0x7;
    pub const WINDOW_UPDATE: u8 = 0x8;
    pub const CONTINUATION: u8 = 0x9;
}

/// Frame flag bits (meaning depends on frame type).
pub mod flag {
    pub const ACK: u8 = 0x1; // SETTINGS, PING
    pub const END_STREAM: u8 = 0x1; // DATA, HEADERS
    pub const END_HEADERS: u8 = 0x4; // HEADERS, CONTINUATION, PUSH_PROMISE
    pub const PADDED: u8 = 0x8; // DATA, HEADERS, PUSH_PROMISE
    pub const PRIORITY: u8 = 0x20; // HEADERS
}

/// SETTINGS parameter identifiers (RFC 9113 §6.5.2).
#[allow(dead_code)] // a complete set of protocol constants
pub mod settings {
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    pub const ENABLE_PUSH: u16 = 0x2;
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
}

/// HTTP/2 error codes (RFC 9113 §7).
#[allow(dead_code)] // a complete set of protocol constants
pub mod errcode {
    pub const NO_ERROR: u32 = 0x0;
    pub const PROTOCOL_ERROR: u32 = 0x1;
    pub const INTERNAL_ERROR: u32 = 0x2;
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    pub const SETTINGS_TIMEOUT: u32 = 0x4;
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    pub const COMPRESSION_ERROR: u32 = 0x9;
    pub const ENHANCE_YOUR_CALM: u32 = 0xb;
}

/// The client connection preface (RFC 9113 §3.4).
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The fixed 9-octet frame header.
#[derive(Debug, Clone, Copy)]
pub struct FrameHeader {
    pub length: usize,
    pub ftype: u8,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    /// Parse a frame header from exactly 9 bytes.
    pub fn parse(buf: &[u8]) -> FrameHeader {
        debug_assert!(buf.len() >= 9);
        let length = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | (buf[2] as usize);
        let ftype = buf[3];
        let flags = buf[4];
        // Top bit of the stream id is reserved and must be ignored.
        let stream_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
        FrameHeader {
            length,
            ftype,
            flags,
            stream_id,
        }
    }

    /// Whether a flag bit is set.
    pub fn has(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

/// Append a complete frame (9-octet header + payload) to `out`.
pub fn write_frame(out: &mut Vec<u8>, ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    let len = payload.len();
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.push(ftype);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Append a SETTINGS frame carrying the given `(id, value)` parameters.
pub fn write_settings(out: &mut Vec<u8>, params: &[(u16, u32)]) {
    let mut payload = Vec::with_capacity(params.len() * 6);
    for (id, value) in params {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    write_frame(out, ftype::SETTINGS, 0, 0, &payload);
}

/// Append a SETTINGS ACK frame.
pub fn write_settings_ack(out: &mut Vec<u8>) {
    write_frame(out, ftype::SETTINGS, flag::ACK, 0, &[]);
}

/// Append a WINDOW_UPDATE frame adding `increment` to `stream_id`'s window
/// (use stream 0 for the connection-level window).
pub fn write_window_update(out: &mut Vec<u8>, stream_id: u32, increment: u32) {
    write_frame(
        out,
        ftype::WINDOW_UPDATE,
        0,
        stream_id,
        &(increment & 0x7fff_ffff).to_be_bytes(),
    );
}

/// Append an RST_STREAM frame.
pub fn write_rst_stream(out: &mut Vec<u8>, stream_id: u32, error_code: u32) {
    write_frame(
        out,
        ftype::RST_STREAM,
        0,
        stream_id,
        &error_code.to_be_bytes(),
    );
}

/// Append a GOAWAY frame.
pub fn write_goaway(out: &mut Vec<u8>, last_stream_id: u32, error_code: u32) {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&(last_stream_id & 0x7fff_ffff).to_be_bytes());
    payload.extend_from_slice(&error_code.to_be_bytes());
    write_frame(out, ftype::GOAWAY, 0, 0, &payload);
}

/// Parse a SETTINGS payload into `(id, value)` pairs. Returns `None` if the
/// payload length is not a multiple of six.
pub fn parse_settings(payload: &[u8]) -> Option<Vec<(u16, u32)>> {
    if !payload.len().is_multiple_of(6) {
        return None;
    }
    Some(
        payload
            .chunks_exact(6)
            .map(|c| {
                let id = u16::from_be_bytes([c[0], c[1]]);
                let value = u32::from_be_bytes([c[2], c[3], c[4], c[5]]);
                (id, value)
            })
            .collect(),
    )
}

/// Strip HTTP/2 DATA/HEADERS padding given the `PADDED` flag. Returns the
/// content slice (between the pad-length octet and the trailing padding), or
/// `None` on a malformed pad length.
pub fn strip_padding(payload: &[u8], padded: bool) -> Option<&[u8]> {
    if !padded {
        return Some(payload);
    }
    let pad_len = *payload.first()? as usize;
    let body = &payload[1..];
    if pad_len > body.len() {
        return None;
    }
    Some(&body[..body.len() - pad_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let mut out = Vec::new();
        write_frame(&mut out, ftype::HEADERS, flag::END_HEADERS, 5, b"abc");
        let h = FrameHeader::parse(&out[..9]);
        assert_eq!(h.length, 3);
        assert_eq!(h.ftype, ftype::HEADERS);
        assert!(h.has(flag::END_HEADERS));
        assert_eq!(h.stream_id, 5);
        assert_eq!(&out[9..], b"abc");
    }

    #[test]
    fn settings_round_trip() {
        let mut out = Vec::new();
        write_settings(&mut out, &[(settings::INITIAL_WINDOW_SIZE, 1 << 20)]);
        let h = FrameHeader::parse(&out[..9]);
        let params = parse_settings(&out[9..9 + h.length]).unwrap();
        assert_eq!(params, vec![(settings::INITIAL_WINDOW_SIZE, 1 << 20)]);
    }

    #[test]
    fn padding_stripped() {
        // pad_len=2, content="hi", padding=2 bytes
        let payload = [2u8, b'h', b'i', 0, 0];
        assert_eq!(strip_padding(&payload, true), Some(&b"hi"[..]));
        assert_eq!(strip_padding(&payload, false), Some(&payload[..]));
        assert_eq!(strip_padding(&[5u8, 1, 2], true), None);
    }
}
