//! Response body compression, negotiated from the request's `Accept-Encoding`.
//!
//! Built on [`compcol`]. Buffered response bodies are compressed in one shot
//! with [`compcol::vec`], which keeps the integration simple and lets us skip
//! compression when it would not actually shrink the body.

use compcol::deflate::Deflate;
use compcol::gzip::Gzip;
use compcol::zlib::Zlib;

use crate::proto::{Request, Response};

/// Knobs controlling response compression.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Master switch.
    pub enabled: bool,
    /// Bodies smaller than this are never compressed (the framing overhead and
    /// CPU rarely pay off for tiny payloads).
    pub min_size: usize,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            enabled: true,
            min_size: 256,
        }
    }
}

/// A content-coding this server can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Coding {
    Gzip,
    /// HTTP `deflate` is, by spec, the zlib format (RFC 1950).
    Deflate,
    /// Raw RFC 1951 deflate. Not negotiated by default but kept available for
    /// callers that build their own coding selection.
    #[allow(dead_code)]
    Raw,
}

impl Coding {
    fn token(self) -> &'static str {
        match self {
            Coding::Gzip => "gzip",
            Coding::Deflate => "deflate",
            Coding::Raw => "deflate",
        }
    }
}

/// Compress `resp`'s body in place if the client accepts a coding we support
/// and the body is a worthwhile candidate. Returns the (possibly unchanged)
/// response.
pub fn compress_response(req: &Request, resp: Response, opts: &Options) -> Response {
    if !opts.enabled {
        return resp;
    }
    // Never double-encode or compress a partial/conditional body we didn't
    // produce here.
    if resp.headers().contains("content-encoding") {
        return resp;
    }
    if resp.body_ref().len() < opts.min_size {
        return resp;
    }
    // Skip already-compressed media types.
    if let Some(ct) = resp.headers().get("content-type")
        && crate::mime::is_precompressed(ct)
    {
        return resp;
    }

    let accept = req.headers().get("accept-encoding").unwrap_or("");
    let Some(coding) = choose_coding(accept) else {
        return resp;
    };

    let (status, mut headers, body) = resp.into_parts();
    let compressed = match coding {
        Coding::Gzip => compcol::vec::compress_to_vec::<Gzip>(&body),
        Coding::Deflate => compcol::vec::compress_to_vec::<Zlib>(&body),
        Coding::Raw => compcol::vec::compress_to_vec::<Deflate>(&body),
    };

    match compressed {
        // Only adopt the compressed form if it is actually smaller.
        Ok(out) if out.len() < body.len() => {
            headers.set("Content-Encoding", coding.token());
            append_vary(&mut headers, "Accept-Encoding");
            Response::from_parts(status, headers, out)
        }
        _ => {
            append_vary(&mut headers, "Accept-Encoding");
            Response::from_parts(status, headers, body)
        }
    }
}

/// Pick the best coding the client will accept, honoring `q=0` opt-outs.
/// Preference order: gzip, then deflate.
fn choose_coding(accept_encoding: &str) -> Option<Coding> {
    let acceptable = |name: &str| accepts(accept_encoding, name);
    if acceptable("gzip") {
        Some(Coding::Gzip)
    } else if acceptable("deflate") {
        Some(Coding::Deflate)
    } else {
        None
    }
}

/// Whether `name` (or `*`) is acceptable per an `Accept-Encoding` header,
/// treating an explicit `q=0` as a refusal.
fn accepts(header: &str, name: &str) -> bool {
    let mut star: Option<bool> = None;
    for part in header.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (token, q) = match part.split_once(';') {
            Some((t, params)) => (t.trim(), parse_q(params)),
            None => (part, 1.0),
        };
        let usable = q > 0.0;
        if token.eq_ignore_ascii_case(name) {
            return usable;
        }
        if token == "*" {
            star = Some(usable);
        }
    }
    star.unwrap_or(false)
}

/// Extract the `q=` value from an `Accept-Encoding` parameter list.
fn parse_q(params: &str) -> f32 {
    for p in params.split(';') {
        let p = p.trim();
        if let Some(v) = p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")) {
            return v.trim().parse().unwrap_or(1.0);
        }
    }
    1.0
}

/// Add `value` to the `Vary` header without duplicating it.
fn append_vary(headers: &mut crate::proto::Headers, value: &str) {
    if headers.contains_token("vary", value) || headers.contains_token("vary", "*") {
        return;
    }
    match headers.get("vary").map(|s| s.to_owned()) {
        Some(existing) => headers.set("Vary", format!("{existing}, {value}")),
        None => headers.set("Vary", value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_encoding_parsing() {
        assert!(accepts("gzip, deflate", "gzip"));
        assert!(accepts("gzip;q=0.8, deflate", "deflate"));
        assert!(!accepts("gzip;q=0", "gzip"));
        assert!(accepts("*", "gzip"));
        assert!(!accepts("*;q=0", "gzip"));
        assert!(!accepts("identity", "gzip"));
    }

    #[test]
    fn chooses_gzip_first() {
        assert_eq!(choose_coding("deflate, gzip"), Some(Coding::Gzip));
        assert_eq!(choose_coding("deflate"), Some(Coding::Deflate));
        assert_eq!(choose_coding("br"), None);
    }
}
