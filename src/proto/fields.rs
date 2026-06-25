//! Shared logic for building a [`Request`] head from HTTP/2 or HTTP/3 header
//! fields (both use the same pseudo-header model, RFC 9113 §8.3 / RFC 9114 §4.3).

use super::{Headers, Method, StatusCode};

/// A request line reconstructed from header fields, before the body is known.
pub(crate) struct RequestHead {
    pub method: Method,
    pub target: String,
    pub headers: Headers,
}

/// Build a [`RequestHead`] from an ordered list of `(name, value)` header
/// fields, validating the pseudo-header rules common to HTTP/2 and HTTP/3:
///
/// - pseudo-headers (`:method`, `:path`, `:scheme`, `:authority`) must precede
///   regular fields and may not repeat;
/// - field names must be lowercase;
/// - connection-specific headers are forbidden;
/// - `:method` and a non-empty `:path` are required.
///
/// Returns `Err(())` on any violation (the caller resets just that stream).
pub(crate) fn request_head<'a, I>(fields: I) -> Result<RequestHead, ()>
where
    I: IntoIterator<Item = (&'a [u8], &'a [u8])>,
{
    let mut method: Option<String> = None;
    let mut path: Option<String> = None;
    let mut authority: Option<String> = None;
    let mut scheme: Option<String> = None;
    let mut headers = Headers::new();
    let mut seen_regular = false;

    for (name, value) in fields {
        if name.first() == Some(&b':') {
            if seen_regular {
                return Err(()); // pseudo-header after a regular header
            }
            let val = String::from_utf8_lossy(value).into_owned();
            match name {
                b":method" => set_once(&mut method, val)?,
                b":path" => set_once(&mut path, val)?,
                b":authority" => set_once(&mut authority, val)?,
                b":scheme" => set_once(&mut scheme, val)?,
                _ => return Err(()), // unknown/invalid pseudo-header
            }
        } else {
            if name.iter().any(|b| b.is_ascii_uppercase()) {
                return Err(());
            }
            match name {
                b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
                | b"upgrade" => return Err(()),
                b"te" if value != b"trailers" => return Err(()),
                _ => {}
            }
            seen_regular = true;
            headers.append(
                String::from_utf8_lossy(name).into_owned(),
                String::from_utf8_lossy(value).into_owned(),
            );
        }
    }

    let _ = scheme; // accepted but not otherwise used by this server
    let method = Method::parse(&method.ok_or(())?);
    let target = path.ok_or(())?;
    if target.is_empty() {
        return Err(());
    }
    if let Some(auth) = authority {
        headers.set_if_absent("host", auth);
    }
    Ok(RequestHead {
        method,
        target,
        headers,
    })
}

/// Build the response header field list shared by HTTP/2 and HTTP/3: the
/// `:status` pseudo-header first, then the lowercased regular headers with the
/// connection-specific (hop-by-hop) headers — illegal in h2/h3 — dropped. A
/// `server` value is appended when the response doesn't already set one.
pub(crate) fn response_fields(
    status: StatusCode,
    headers: &Headers,
    server: Option<&str>,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut fields: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(headers.len() + 2);
    fields.push((b":status".to_vec(), status.code().to_string().into_bytes()));

    let mut has_server = false;
    for (name, value) in headers.iter() {
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" => {
                continue;
            }
            "server" => has_server = true,
            _ => {}
        }
        fields.push((lower.into_bytes(), value.as_bytes().to_vec()));
    }
    if !has_server && let Some(s) = server {
        fields.push((b"server".to_vec(), s.as_bytes().to_vec()));
    }
    fields
}

fn set_once(slot: &mut Option<String>, value: String) -> Result<(), ()> {
    if slot.is_some() {
        return Err(());
    }
    *slot = Some(value);
    Ok(())
}
