//! A [`Handler`] that serves files from a directory on disk.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::UNIX_EPOCH;

use crate::handler::Handler;
use crate::mime;
use crate::proto::{Body, Method, Request, Response, StatusCode};

/// Race-free confined file opening beneath the static-file root.
///
/// Uses `openat2(2)` with `RESOLVE_BENEATH` so path resolution is confined
/// strictly beneath the root dirfd: `..` escaping the root, absolute symlinks,
/// and symlinks whose target leaves the root all fail atomically, while in-root
/// symlinks still resolve. Making open+confinement a single syscall closes the
/// TOCTOU window between the old canonicalize check and `File::open`.
///
/// This module is the other scoped `unsafe` user besides `privdrop`; it opts
/// back in under the crate's `deny(unsafe_code)` with a local `allow`.
#[cfg(all(feature = "hardened-fs", target_os = "linux"))]
#[allow(unsafe_code)]
mod confined {
    use std::ffi::CString;
    use std::io;
    use std::mem::size_of;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::path::Path;
    use std::sync::atomic::{AtomicU8, Ordering};

    /// `RESOLVE_BENEATH`: reject any resolution step that would escape the
    /// dirfd (`..` above it, absolute paths, out-of-tree symlink targets).
    const RESOLVE_BENEATH: u64 = 0x08;
    /// `openat2(2)` syscall number — identical (437) across all Linux
    /// architectures, hardcoded because a matching libc const may be absent.
    const SYS_OPENAT2: libc::c_long = 437;

    /// Whether `openat2` is available on the running kernel: 0 = unknown,
    /// 1 = yes, 2 = no. Caches an `ENOSYS` result so an old kernel is probed
    /// once, not per request.
    static SUPPORTED: AtomicU8 = AtomicU8::new(0);

    /// Mirror of the kernel's `struct open_how` (see `openat2(2)`).
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    fn path_to_cstring(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
    }

    /// Open `rel` (a relative path) for reading, confined strictly beneath
    /// `root`.
    ///
    /// Returns `Ok(None)` when `openat2` is unavailable (old kernel: `ENOSYS`),
    /// signalling the caller to use the canonicalize-based fallback. Any other
    /// failure — including confinement rejections (`EXDEV`, `ELOOP`, `ENOTDIR`)
    /// and `ENOENT` — is returned as `Err` for the caller to map to 404.
    pub fn open_beneath(root: &Path, rel: &Path) -> io::Result<Option<std::fs::File>> {
        // Old kernel already detected: skip the syscall entirely.
        if SUPPORTED.load(Ordering::Relaxed) == 2 {
            return Ok(None);
        }

        let root_c = path_to_cstring(root)?;
        let rel_c = path_to_cstring(rel)?;

        // Open the root as an `O_PATH` directory fd. SAFETY: `root_c` is a valid
        // NUL-terminated C string; the flags are valid; the return value is
        // checked below.
        let raw_dir = unsafe {
            libc::open(
                root_c.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw_dir < 0 {
            return Err(io::Error::last_os_error());
        }
        // Wrap immediately so the dirfd is closed (RAII) on every return path.
        // SAFETY: `raw_dir` is a fresh, owned, valid fd we just obtained.
        let dirfd = unsafe { std::fs::File::from_raw_fd(raw_dir) };

        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH,
        };

        // SAFETY: `dirfd` is a valid open directory fd; `rel_c` is a valid
        // NUL-terminated C string; `&how` points to a live, correctly laid-out
        // `struct open_how` and we pass its exact size. The return value is
        // checked below before any use.
        let ret = unsafe {
            libc::syscall(
                SYS_OPENAT2,
                dirfd.as_raw_fd(),
                rel_c.as_ptr(),
                &how as *const OpenHow,
                size_of::<OpenHow>(),
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOSYS) {
                SUPPORTED.store(2, Ordering::Relaxed);
                return Ok(None);
            }
            return Err(err);
        }

        SUPPORTED.store(1, Ordering::Relaxed);
        // SAFETY: `ret` is a fresh, owned, valid fd returned by openat2.
        let file = unsafe { std::fs::File::from_raw_fd(ret as libc::c_int) };
        Ok(Some(file))
    }
}

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
    /// Canonicalized root, computed lazily on first successful canonicalization
    /// and reused thereafter. Avoids re-canonicalizing the root on every request
    /// (which would make confinement depend on transient FS state and repeat
    /// work). If the root cannot be canonicalized yet (e.g. it does not exist),
    /// the cell stays empty and confinement fails closed.
    root_canon: OnceLock<PathBuf>,
}

impl StaticFiles {
    /// Serve files from `root`, using `index.html` as the directory index.
    pub fn new(root: impl Into<PathBuf>) -> StaticFiles {
        StaticFiles {
            root: root.into(),
            index: "index.html".to_owned(),
            root_canon: OnceLock::new(),
        }
    }

    /// The canonical root, computed once and cached. Returns `None` if the root
    /// cannot currently be canonicalized (e.g. it does not exist yet).
    fn canonical_root(&self) -> Option<&Path> {
        if let Some(root) = self.root_canon.get() {
            return Some(root.as_path());
        }
        // Attempt to canonicalize; only cache on success so a transient failure
        // (root not yet created) can be retried on a later request.
        match fs::canonicalize(&self.root) {
            Ok(root) => Some(self.root_canon.get_or_init(|| root).as_path()),
            Err(_) => None,
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
        // Fail closed: refuse if the root cannot be canonicalized (cached once)
        // or the candidate path cannot be canonicalized.
        match (self.canonical_root(), fs::canonicalize(path)) {
            (Some(root), Ok(target)) => target.starts_with(root),
            _ => false,
        }
    }

    /// Open `path` (which is `self.root` + validated segments) for reading,
    /// confined beneath the root so no symlink/rename race can escape. Returns
    /// Ok(None) when confined open is unavailable (non-Linux build, or a kernel
    /// without openat2) so the caller uses the canonicalize-based fallback.
    #[cfg(all(feature = "hardened-fs", target_os = "linux"))]
    fn open_confined(&self, path: &Path) -> io::Result<Option<fs::File>> {
        // `resolve` builds `root + segments`, so stripping the root yields the
        // relative path to open beneath the root dirfd. If it somehow fails,
        // fall back rather than risk an unconfined open.
        let Ok(rel) = path.strip_prefix(&self.root) else {
            return Ok(None);
        };
        confined::open_beneath(&self.root, rel)
    }

    /// Fallback stub on non-Linux builds or without `hardened-fs`: confined open
    /// is unavailable, so always fall back to the canonicalize-based path.
    #[cfg(not(all(feature = "hardened-fs", target_os = "linux")))]
    fn open_confined(&self, path: &Path) -> io::Result<Option<fs::File>> {
        let _ = path;
        Ok(None)
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

        // Acquire the file and its metadata race-free. On Linux with
        // `hardened-fs`, `open_confined` opens beneath the root via
        // `openat2(RESOLVE_BENEATH)`, so open+confinement is a single atomic
        // syscall (no TOCTOU window). When confined open is unavailable it
        // returns `Ok(None)` and we take the historical canonicalize fallback.
        let (file, meta) = match self.open_confined(&path) {
            // Confined open succeeded: the open IS the confinement, so we do NOT
            // re-run `within_root`. Just fstat the fd to confirm it is a file.
            Ok(Some(file)) => {
                let meta = match file.metadata() {
                    Ok(m) if m.is_file() => m,
                    _ => return Response::status(StatusCode::NOT_FOUND),
                };
                (file, meta)
            }
            // Fallback path (non-Linux, or a kernel without openat2): do exactly
            // what the code did historically — is_file stat, `within_root`
            // confinement, then a plain open.
            Ok(None) => {
                let meta = match fs::metadata(&path) {
                    Ok(m) if m.is_file() => m,
                    _ => return Response::status(StatusCode::NOT_FOUND),
                };
                if !self.within_root(&path) {
                    // A target that escapes the root (e.g. via a symlink) is
                    // reported as `404` — indistinguishable from a missing file
                    // — so it cannot be used as an existence/symlink oracle,
                    // matching the dotfile policy.
                    return Response::status(StatusCode::NOT_FOUND);
                }
                let file = match fs::File::open(&path) {
                    Ok(f) => f,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        return Response::status(StatusCode::NOT_FOUND);
                    }
                    Err(_) => return Response::status(StatusCode::INTERNAL_SERVER_ERROR),
                };
                (file, meta)
            }
            // A confined-open error: missing, or a confinement rejection
            // (ELOOP/EXDEV/ENOTDIR from an escaping symlink/`..`), or a
            // permission error. All are reported as `404` — indistinguishable
            // from a missing file — so an escape cannot be used as an oracle.
            Err(_) => return Response::status(StatusCode::NOT_FOUND),
        };

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

        // The file was opened above (confined on Linux/`hardened-fs`, plain
        // otherwise). The fd is shared via `Arc` and the body is streamed off it
        // in bounded chunks (200 and 206 alike) — the whole file is never
        // buffered. A HEAD still produces a `Body::File` so `Content-Length` is
        // correct, but the engines skip the read for bodyless responses.
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
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
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
    fn percent_decoding_trailing_triplet() {
        // A complete `%XX` triplet at the very end of the string must decode;
        // previously an off-by-one bound left the final triplet un-decoded,
        // a normalization inconsistency usable as a filter-bypass primitive.
        assert_eq!(percent_decode("/foo%2e"), "/foo.");
        assert_eq!(percent_decode("/foo%2f"), "/foo/");
        assert_eq!(percent_decode("%2e"), ".");
        assert_eq!(percent_decode("/a%2e%2e"), "/a..");
        // An incomplete trailing escape is still passed through verbatim.
        assert_eq!(percent_decode("/foo%2"), "/foo%2");
        assert_eq!(percent_decode("/foo%"), "/foo%");
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

    // Build a unique scratch directory under the system temp dir.
    fn scratch_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "httpsd-static-test-{}-{}-{}-{}",
            tag,
            std::process::id(),
            n,
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn get(path: &str) -> Request {
        Request::new(
            Method::Get,
            path.to_owned(),
            crate::proto::Version::Http11,
            crate::proto::Headers::new(),
            Vec::new(),
        )
    }

    #[test]
    fn served_file_and_traversal_blocked_on_disk() {
        let root = scratch_dir("serve");
        fs::write(root.join("hello.txt"), b"hi").unwrap();
        let sf = StaticFiles::new(&root);

        // A real file inside the root is served.
        assert_eq!(sf.serve(&get("/hello.txt")).status_code().code(), 200);

        // Traversal is still blocked (reported as 404, existence not confirmed).
        assert_eq!(sf.serve(&get("/../hello.txt")).status_code().code(), 404);
        assert_eq!(
            sf.serve(&get("/%2e%2e/hello.txt")).status_code().code(),
            404
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_404_not_403() {
        // A symlink inside the root that points to a real file OUTSIDE the root
        // must be reported as 404 (indistinguishable from a missing file), not
        // 403 — otherwise it is an existence/symlink oracle.
        let base = scratch_dir("symlink");
        let root = base.join("root");
        let outside = base.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();

        let secret = outside.join("secret.txt");
        fs::write(&secret, b"top secret").unwrap();

        // root/leak.txt -> ../outside/secret.txt (escapes the root).
        let link = root.join("leak.txt");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let sf = StaticFiles::new(&root);

        // The confinement check must reject the escaped target.
        assert!(!sf.within_root(&link));
        // And the served response must be 404, not 403.
        assert_eq!(sf.serve(&get("/leak.txt")).status_code().code(), 404);

        // A genuinely missing file also yields 404 — the two are indistinguishable.
        assert_eq!(sf.serve(&get("/nope.txt")).status_code().code(), 404);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn canonical_root_cached_after_first_success() {
        let root = scratch_dir("cache");
        let sf = StaticFiles::new(&root);
        // First access canonicalizes and caches.
        let first = sf.canonical_root().map(|p| p.to_owned());
        assert!(first.is_some());
        assert!(sf.root_canon.get().is_some());
        // Even if the underlying directory disappears, the cached value persists,
        // so confinement no longer depends on transient FS state per request.
        let _ = fs::remove_dir_all(&root);
        assert_eq!(sf.canonical_root().map(|p| p.to_owned()), first);
    }

    // --- confined-open (openat2 RESOLVE_BENEATH) tests -----------------------

    #[cfg(all(feature = "hardened-fs", target_os = "linux"))]
    #[test]
    fn confined_serves_in_root_file() {
        // A normal in-root file is served (200) through the confined open path.
        let root = scratch_dir("confined-ok");
        fs::write(root.join("hello.txt"), b"hi").unwrap();
        let sf = StaticFiles::new(&root);
        assert_eq!(sf.serve(&get("/hello.txt")).status_code().code(), 200);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(all(feature = "hardened-fs", target_os = "linux"))]
    #[test]
    fn confined_symlink_escape_is_404() {
        // A symlink inside the root pointing OUTSIDE the root must be rejected
        // by the confined open (EXDEV/ELOOP) and reported as 404.
        let base = scratch_dir("confined-escape");
        let root = base.join("root");
        let outside = base.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();

        let secret = outside.join("secret.txt");
        fs::write(&secret, b"top secret").unwrap();
        let link = root.join("leak.txt");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let sf = StaticFiles::new(&root);
        assert_eq!(sf.serve(&get("/leak.txt")).status_code().code(), 404);
        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(all(feature = "hardened-fs", target_os = "linux"))]
    #[test]
    fn confined_allows_in_root_symlink() {
        // RESOLVE_BENEATH still permits legitimate symlinks that stay inside the
        // root: root/link.txt -> real.txt (both in root) must be served (200).
        let root = scratch_dir("confined-inlink");
        fs::write(root.join("real.txt"), b"payload").unwrap();
        std::os::unix::fs::symlink("real.txt", root.join("link.txt")).unwrap();

        let sf = StaticFiles::new(&root);
        assert_eq!(sf.serve(&get("/link.txt")).status_code().code(), 200);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(all(feature = "hardened-fs", target_os = "linux"))]
    #[test]
    fn open_confined_unit() {
        // Direct unit test of open_confined / confined::open_beneath: an
        // escaping relative path is rejected (Err), a valid one opens (Ok(Some)).
        let base = scratch_dir("confined-unit");
        let root = base.join("root");
        let outside = base.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(root.join("real.txt"), b"payload").unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();
        // root/leak.txt -> ../outside/secret.txt (escapes the root).
        std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("leak.txt")).unwrap();

        let sf = StaticFiles::new(&root);

        // A valid in-root file opens.
        let ok = sf.open_confined(&root.join("real.txt")).unwrap();
        assert!(ok.is_some());

        // An escaping symlink is rejected — openat2 returns an error (not None,
        // which would signal an unsupported kernel).
        let escaped = sf.open_confined(&root.join("leak.txt"));
        assert!(escaped.is_err());

        // And at the raw layer, `..` escaping the root is rejected too.
        let up = confined::open_beneath(&root, Path::new("../outside/secret.txt"));
        assert!(up.is_err());

        let _ = fs::remove_dir_all(&base);
    }
}
