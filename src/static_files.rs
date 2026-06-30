//! A [`Handler`] that serves files from a directory on disk.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use crate::handler::Handler;
use crate::mime;
use crate::proto::{Body, Method, Request, Response, StatusCode};

/// Serves static files rooted at a directory.
///
/// Security: request paths are percent-decoded, normalized, and any `..`
/// component is rejected, so a request can never escape the configured root.
/// Symlinks that point outside the root are also rejected via canonicalization.
///
/// Behavior:
/// - `GET` and `HEAD` are supported; other methods get `405`.
/// - A request for a directory serves its `index.html` if present, else `404`
///   (directory listings are intentionally not generated).
/// - `Last-Modified` and a weak-ish `ETag` are emitted; `If-None-Match` and
///   `If-Modified-Since` produce `304` when they match.
/// - A single `Range` request is honored with a `206` response; multi-range
///   requests fall back to the full body.
#[derive(Debug, Clone)]
pub struct StaticFiles {
    root: PathBuf,
    index: String,
}

impl StaticFiles {
    /// Serve files from `root`, using `index.html` as the directory index.
    pub fn new(root: impl Into<PathBuf>) -> StaticFiles {
        StaticFiles {
            root: root.into(),
            index: "index.html".to_owned(),
        }
    }

    /// Override the directory index file name (default `index.html`).
    pub fn index(mut self, name: impl Into<String>) -> StaticFiles {
        self.index = name.into();
        self
    }

    /// Resolve a request path to a file path inside the root, or `None` if the
    /// path is unsafe.
    fn resolve(&self, req_path: &str) -> Option<PathBuf> {
        let decoded = percent_decode(req_path);
        let mut out = self.root.clone();
        for seg in decoded.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                return None; // never allow upward traversal
            }
            // Reject dotfiles/dotdirs (`.git`, `.env`, …) to avoid leaking
            // sensitive files. The handler turns `None` into a `404` so we do
            // not confirm their existence.
            if seg.starts_with('.') {
                return None;
            }
            // Reject embedded NULs and path separators that survived decoding.
            if seg.contains('\0') || seg.contains('/') || seg.contains('\\') {
                return None;
            }
            out.push(seg);
        }
        Some(out)
    }

    /// Final defense: ensure the canonical target stays within the canonical
    /// root (defeats symlink escapes).
    fn within_root(&self, path: &Path) -> bool {
        match (fs::canonicalize(&self.root), fs::canonicalize(path)) {
            (Ok(root), Ok(target)) => target.starts_with(root),
            _ => false,
        }
    }

    fn serve(&self, req: &Request) -> Response {
        if !matches!(req.method(), Method::Get | Method::Head) {
            return Response::status(StatusCode::METHOD_NOT_ALLOWED).header("Allow", "GET, HEAD");
        }

        let Some(mut path) = self.resolve(req.path()) else {
            // Unsafe paths (traversal, dotfiles, …) are reported as `404` so we
            // never confirm whether a rejected target exists.
            return Response::status(StatusCode::NOT_FOUND);
        };

        // Directory → index file.
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => return Response::status(StatusCode::NOT_FOUND),
        };
        if meta.is_dir() {
            // Redirect "/dir" → "/dir/" so relative links resolve correctly.
            if !req.path().ends_with('/') {
                let mut loc = req.path().to_owned();
                loc.push('/');
                if let Some(q) = req.query() {
                    loc.push('?');
                    loc.push_str(q);
                }
                return Response::redirect(StatusCode::MOVED_PERMANENTLY, loc);
            }
            path.push(&self.index);
        }

        let meta = match fs::metadata(&path) {
            Ok(m) if m.is_file() => m,
            _ => return Response::status(StatusCode::NOT_FOUND),
        };
        if !self.within_root(&path) {
            return Response::status(StatusCode::FORBIDDEN);
        }

        let content_type = mime::from_path(path.to_string_lossy().as_ref());
        let len = meta.len();
        let mtime_secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        let last_modified = mtime_secs.map(crate::proto::http_date);
        let etag = format!("\"{:x}-{:x}\"", len, mtime_secs.unwrap_or(0));

        // Conditional requests.
        if conditional_hit(req, &etag, last_modified.as_deref()) {
            let mut resp = Response::new(StatusCode::NOT_MODIFIED).header("ETag", etag.clone());
            if let Some(lm) = &last_modified {
                resp = resp.header("Last-Modified", lm.clone());
            }
            return resp;
        }

        // Open the file once, here, so a permission/existence error becomes a
        // clean status BEFORE any headers are committed. The fd is shared via
        // `Arc` and the body is streamed off it in bounded chunks (200 and 206
        // alike) — the whole file is never buffered. A HEAD still produces a
        // `Body::File` so `Content-Length` is correct, but the engines skip the
        // read for bodyless responses.
        let file = match fs::File::open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Response::status(StatusCode::NOT_FOUND);
            }
            Err(_) => return Response::status(StatusCode::INTERNAL_SERVER_ERROR),
        };
        let file = Arc::new(file);

        // Range handling (single range only). A satisfiable range streams exactly
        // the requested span off disk.
        if let Some(range) = req.headers().get("range") {
            if let Some((start, end)) = parse_single_range(range, len) {
                let mut resp = Response::new(StatusCode::PARTIAL_CONTENT)
                    .header("Content-Type", content_type)
                    .header("Accept-Ranges", "bytes")
                    .header("X-Content-Type-Options", "nosniff")
                    .header("Content-Range", format!("bytes {start}-{end}/{len}"))
                    .header("ETag", etag);
                if let Some(lm) = last_modified {
                    resp = resp.header("Last-Modified", lm);
                }
                return resp.body(Body::file(file, start, end - start + 1));
            } else if range.trim_start().starts_with("bytes=") {
                // A syntactically present but unsatisfiable range.
                return Response::new(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header("Content-Range", format!("bytes */{len}"));
            }
        }

        let mut resp = Response::new(StatusCode::OK)
            .header("Content-Type", content_type)
            .header("Accept-Ranges", "bytes")
            .header("X-Content-Type-Options", "nosniff")
            .header("ETag", etag);
        if let Some(lm) = last_modified {
            resp = resp.header("Last-Modified", lm);
        }
        resp.body(Body::file(file, 0, len))
    }
}

impl Handler for StaticFiles {
    fn handle(&self, req: &Request) -> Response {
        self.serve(req)
    }
}

/// Whether a conditional request's preconditions say "not modified".
fn conditional_hit(req: &Request, etag: &str, last_modified: Option<&str>) -> bool {
    if let Some(inm) = req.headers().get("if-none-match") {
        return inm == "*" || inm.split(',').any(|t| t.trim() == etag);
    }
    if let (Some(ims), Some(lm)) = (req.headers().get("if-modified-since"), last_modified) {
        return ims == lm;
    }
    false
}

/// Parse a single `Range: bytes=...` value into an inclusive `(start, end)`,
/// clamped to `total`. Returns `None` for multi-range, syntactically invalid,
/// or unsatisfiable ranges.
fn parse_single_range(value: &str, total: u64) -> Option<(u64, u64)> {
    let spec = value.trim().strip_prefix("bytes=")?;
    if spec.contains(',') || total == 0 {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    let (start, end) = match (a.is_empty(), b.is_empty()) {
        // "-N": last N bytes.
        (true, false) => {
            let n: u64 = b.parse().ok()?;
            if n == 0 {
                return None;
            }
            let n = n.min(total);
            (total - n, total - 1)
        }
        // "M-": from M to end.
        (false, true) => {
            let start: u64 = a.parse().ok()?;
            (start, total - 1)
        }
        // "M-N".
        (false, false) => {
            let start: u64 = a.parse().ok()?;
            let end: u64 = b.parse().ok()?;
            (start, end.min(total - 1))
        }
        (true, true) => return None,
    };
    if start > end || start >= total {
        return None;
    }
    Some((start, end))
}

/// Decode `%XX` escapes and `+` (left as-is; `+` is only a space in query
/// strings, not paths). Invalid escapes are passed through verbatim.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_parsing() {
        assert_eq!(parse_single_range("bytes=0-4", 10), Some((0, 4)));
        assert_eq!(parse_single_range("bytes=5-", 10), Some((5, 9)));
        assert_eq!(parse_single_range("bytes=-3", 10), Some((7, 9)));
        assert_eq!(parse_single_range("bytes=8-100", 10), Some((8, 9)));
        assert_eq!(parse_single_range("bytes=0-4,6-7", 10), None);
        assert_eq!(parse_single_range("bytes=20-30", 10), None);
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("/a%20b"), "/a b");
        assert_eq!(percent_decode("/%2e%2e"), "/..");
        assert_eq!(percent_decode("/bad%2"), "/bad%2");
    }

    #[test]
    fn traversal_rejected() {
        let sf = StaticFiles::new("/srv/www");
        assert!(sf.resolve("/../etc/passwd").is_none());
        assert!(sf.resolve("/a/%2e%2e/b").is_none());
        assert_eq!(
            sf.resolve("/sub/file.txt"),
            Some(PathBuf::from("/srv/www/sub/file.txt"))
        );
    }

    #[test]
    fn dotfiles_rejected() {
        let sf = StaticFiles::new("/srv/www");
        // Top-level and nested dotfiles/dotdirs are refused.
        assert!(sf.resolve("/.env").is_none());
        assert!(sf.resolve("/.git/config").is_none());
        assert!(sf.resolve("/sub/.htpasswd").is_none());
        assert!(sf.resolve("/%2egit/config").is_none());
        // Ordinary files with dots elsewhere are still fine.
        assert_eq!(
            sf.resolve("/a.b.txt"),
            Some(PathBuf::from("/srv/www/a.b.txt"))
        );
    }

    #[test]
    fn dotfile_request_is_404() {
        let sf = StaticFiles::new("/srv/www");
        let req = Request::new(
            Method::Get,
            "/.git/config".to_owned(),
            crate::proto::Version::Http11,
            crate::proto::Headers::new(),
            Vec::new(),
        );
        // Rejected paths report 404 (not 403) so existence is not confirmed.
        assert_eq!(sf.serve(&req).status_code().code(), 404);
    }
}
