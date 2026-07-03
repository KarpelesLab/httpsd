//! The plain-HTTP listener: serves ACME HTTP-01 challenges and, by default,
//! redirects everything else to HTTPS (the reason this server is `httpsd`).
//! With `allow_http` it serves content over HTTP instead of redirecting.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Instant;

use crate::error::Result;
use crate::handler::Handler;
use crate::net::gdns;
use crate::proto::{H1Conn, Limits, Request, Response, StatusCode};
use crate::rt::common::{IO_TIMEOUT, MIN_PROGRESS, READ_BUF};

#[cfg(feature = "acme")]
use crate::acme::AcmeManager;
#[cfg(feature = "compress")]
use crate::compress;

/// Settings for the HTTP listener.
#[derive(Clone)]
pub(crate) struct HttpCtx {
    /// Serve content over HTTP instead of redirecting to HTTPS.
    pub allow_http: bool,
    pub server_name: Option<String>,
    pub limits: Limits,
    /// Handler used when `allow_http` is set.
    pub content: Option<Arc<dyn Handler>>,
    #[cfg(feature = "acme")]
    pub acme: Option<AcmeManager>,
    #[cfg(feature = "compress")]
    pub compression: compress::Options,
}

/// Whether a connection has failed the minimum-throughput rule: it has not
/// delivered at least [`MIN_PROGRESS`] bytes within an [`IO_TIMEOUT`] window.
///
/// This mirrors the check in `common::serve_blocking_prefed`: the per-read
/// socket timeout only fires on a *fully idle* read, so a slow-trickle
/// slowloris that dribbles a byte just under the timeout resets it forever. The
/// throughput floor sheds that. A redirect only needs the request line + Host,
/// so the tiny [`MIN_PROGRESS`] floor is easily cleared by any real client.
fn min_progress_exceeded(bytes: usize, elapsed: std::time::Duration) -> bool {
    bytes < MIN_PROGRESS && elapsed >= IO_TIMEOUT
}

/// Serve one plain-HTTP connection.
pub(crate) fn serve(stream: &mut TcpStream, ctx: &HttpCtx) -> Result<()> {
    let local_ip = stream.local_addr()?.ip();
    let mut conn = H1Conn::new(ctx.limits);
    conn.set_server_name(ctx.server_name.clone());

    let mut buf = [0u8; READ_BUF];
    // Minimum-throughput window that defeats slow-trickle slowloris (mirrors the
    // MIN_PROGRESS floor in common::serve_blocking_prefed). The socket read
    // timeout alone only catches a fully idle read; this requires the peer to
    // deliver at least MIN_PROGRESS bytes per IO_TIMEOUT window.
    let mut window_start = Instant::now();
    let mut window_bytes: usize = 0;
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        window_bytes = window_bytes.saturating_add(n);
        if window_bytes >= MIN_PROGRESS {
            // Floor met: open a fresh window.
            window_start = Instant::now();
            window_bytes = 0;
        } else if min_progress_exceeded(window_bytes, window_start.elapsed()) {
            break; // trickle: closed without making real progress
        }
        conn.feed(&buf[..n]);
        while let Ok(Some(req)) = conn.poll_request() {
            let resp = respond(&req, local_ip, ctx);
            conn.respond(resp);
        }
        let out = conn.take_out();
        if !out.is_empty() {
            stream.write_all(&out)?;
            stream.flush()?;
        }
        if conn.wants_close() {
            break;
        }
    }
    Ok(())
}

fn respond(req: &Request, local_ip: std::net::IpAddr, ctx: &HttpCtx) -> Response {
    // ACME HTTP-01: serve the key authorization for a known token.
    #[cfg(feature = "acme")]
    if let Some(mgr) = &ctx.acme
        && let Some(token) = req.path().strip_prefix("/.well-known/acme-challenge/")
    {
        return match mgr.http_challenge(token) {
            Some(key_auth) => Response::new(StatusCode::OK)
                .header("Content-Type", "application/octet-stream")
                .body(key_auth),
            None => Response::status(StatusCode::NOT_FOUND),
        };
    }

    // Serve content over HTTP only when explicitly allowed.
    if ctx.allow_http
        && let Some(handler) = &ctx.content
    {
        let resp = handler.handle(req);
        #[cfg(feature = "compress")]
        let resp = compress::compress_response(req, resp, &ctx.compression);
        return resp;
    }

    // Otherwise upgrade to HTTPS (308 keeps the method/body).
    let location = gdns::redirect_location(req.host(), local_ip, req.target());
    Response::redirect(StatusCode::PERMANENT_REDIRECT, location)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn min_progress_ok_when_floor_met() {
        // Enough bytes: never a trickle regardless of elapsed time.
        assert!(!min_progress_exceeded(MIN_PROGRESS, IO_TIMEOUT));
        assert!(!min_progress_exceeded(MIN_PROGRESS + 1, IO_TIMEOUT * 2));
    }

    #[test]
    fn min_progress_ok_when_window_not_elapsed() {
        // Below the floor but the window has not expired yet: still allowed.
        assert!(!min_progress_exceeded(0, Duration::ZERO));
        assert!(!min_progress_exceeded(
            MIN_PROGRESS - 1,
            IO_TIMEOUT - Duration::from_millis(1)
        ));
    }

    #[test]
    fn min_progress_trips_on_slow_trickle() {
        // Below the floor and the window has expired: shed the connection.
        assert!(min_progress_exceeded(0, IO_TIMEOUT));
        assert!(min_progress_exceeded(MIN_PROGRESS - 1, IO_TIMEOUT * 2));
    }
}
