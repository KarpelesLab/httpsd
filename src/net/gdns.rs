//! IP-to-`g-dns.net` host encoding and the HTTP→HTTPS redirect policy.
//!
//! When a plain-HTTP (or otherwise host-less) request hits the server by IP, we
//! can't redirect to a usable HTTPS host — there's no certificate for a bare IP.
//! Instead we redirect to `<base32(ip)>.g-dns.net`, a wildcard zone that
//! resolves each encoded label back to the embedded address, so the follow-up
//! HTTPS request arrives with a real SNI host we can obtain a certificate for.
//!
//! The base32 alphabet matches the Go encoder this scheme was defined with:
//! `base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(NoPadding)`.

use std::net::IpAddr;

/// The lowercase RFC 4648 base32 alphabet used by the g-dns scheme.
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The DNS zone encoded addresses live under.
pub const GDNS_ZONE: &str = "g-dns.net";

/// Base32-encode bytes with the g-dns alphabet and no padding.
pub fn base32_nopad(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        // Pad the remaining bits on the right to a full 5-bit group.
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// The `g-dns.net` host for an IP address: `<base32(octets)>.g-dns.net`.
/// IPv4 uses the 4-byte form; IPv6 the 16-byte form.
pub fn gdns_host(ip: IpAddr) -> String {
    let label = match ip {
        IpAddr::V4(v4) => base32_nopad(&v4.octets()),
        IpAddr::V6(v6) => base32_nopad(&v6.octets()),
    };
    format!("{label}.{GDNS_ZONE}")
}

/// Strip a trailing `:port` from a `Host` header value, leaving the host.
/// Handles bracketed IPv6 literals (`[::1]:443`).
fn host_only(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        // [ipv6]:port or [ipv6]
        return rest.split(']').next().unwrap_or(rest);
    }
    match authority.rsplit_once(':') {
        // Only treat the suffix as a port if it's numeric (avoids cutting a
        // bare IPv6 with no brackets, which has many colons).
        Some((h, p)) if !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => h,
        _ => authority,
    }
}

/// Decide the HTTPS redirect target for an incoming HTTP request.
///
/// - A real DNS `Host` is preserved: `http://example.com/x` → `https://example.com/x`.
/// - A missing host, or a host that is a bare IP literal, becomes the
///   g-dns host for `local_ip` (the address the client connected to):
///   `http://203.0.113.7/x` → `https://<base32(203.0.113.7)>.g-dns.net/x`.
///
/// `target` is the request target (path plus optional query), used verbatim.
///
/// Defense in depth against response-header (`Location`) injection: although the
/// HTTP/1 parser is the primary guard, both `authority` and `target` originate
/// in the request, so any control byte (`< 0x20`, or `0x7f` DEL) found here is
/// treated as hostile — the authority falls back to the g-dns host and the
/// target to `/`, rather than splicing CR/LF (or other controls) into the
/// emitted `Location` header.
pub fn redirect_location(host_header: Option<&str>, local_ip: IpAddr, target: &str) -> String {
    let authority = match host_header.map(host_only) {
        Some(h) if !h.is_empty() && h.parse::<IpAddr>().is_err() && is_clean(h) => h.to_owned(),
        _ => gdns_host(local_ip),
    };
    let target = if is_clean(target) { target } else { "/" };
    format!("https://{authority}{target}")
}

/// Whether `s` is free of control characters (bytes `< 0x20` or the `0x7f` DEL),
/// which must never appear in a `Location` header value.
fn is_clean(s: &str) -> bool {
    !s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn base32_known_vectors() {
        assert_eq!(base32_nopad(&[0, 0, 0, 0]), "aaaaaaa");
        assert_eq!(base32_nopad(&[255, 255, 255, 255]), "777777y");
        // 5 bytes encode to exactly 8 chars (no padding char emitted).
        assert_eq!(base32_nopad(&[0xff; 5]).len(), 8);
        // IPv4 -> 7 chars, IPv6 -> 26 chars.
        assert_eq!(base32_nopad(&[1, 2, 3, 4]).len(), 7);
        assert_eq!(base32_nopad(&[0u8; 16]).len(), 26);
    }

    #[test]
    fn gdns_host_suffix() {
        let h = gdns_host(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(h, "aaaaaaa.g-dns.net");
        assert!(gdns_host(IpAddr::V6(Ipv6Addr::LOCALHOST)).ends_with(".g-dns.net"));
    }

    #[test]
    fn host_only_strips_port() {
        assert_eq!(host_only("example.com:8080"), "example.com");
        assert_eq!(host_only("example.com"), "example.com");
        assert_eq!(host_only("[::1]:443"), "::1");
        assert_eq!(host_only("1.2.3.4:80"), "1.2.3.4");
    }

    #[test]
    fn redirect_preserves_real_host() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(
            redirect_location(Some("example.com"), ip, "/a?b=1"),
            "https://example.com/a?b=1"
        );
        assert_eq!(
            redirect_location(Some("example.com:8080"), ip, "/"),
            "https://example.com/"
        );
    }

    #[test]
    fn redirect_strips_control_chars() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        // A CR/LF (or other control) in the host falls back to the g-dns host.
        let host_fallback = format!("https://{}/p", gdns_host(ip));
        assert_eq!(
            redirect_location(Some("evil.com\r\nX-Injected: 1"), ip, "/p"),
            host_fallback
        );
        // A control char in the target falls back to "/".
        assert_eq!(
            redirect_location(Some("example.com"), ip, "/a\r\nSet-Cookie: x"),
            "https://example.com/"
        );
        // A bare DEL byte is rejected too.
        assert_eq!(
            redirect_location(Some("example.com"), ip, "/a\x7fb"),
            "https://example.com/"
        );
    }

    #[test]
    fn redirect_ip_or_missing_goes_to_gdns() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let expect = format!("https://{}/p", gdns_host(ip));
        assert_eq!(redirect_location(Some("203.0.113.7"), ip, "/p"), expect);
        assert_eq!(redirect_location(None, ip, "/p"), expect);
    }
}
