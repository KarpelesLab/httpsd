//! The plain-HTTP listener: serves ACME HTTP-01 challenges and, by default,
//! redirects everything else to HTTPS (the reason this server is `httpsd`).
//! With `allow_http` it serves content over HTTP instead of redirecting.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use crate::error::Result;
use crate::handler::Handler;
use crate::net::gdns;
use crate::proto::{H1Conn, Limits, Request, Response, StatusCode};
use crate::rt::common::READ_BUF;

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

/// Serve one plain-HTTP connection.
pub(crate) fn serve(stream: &mut TcpStream, ctx: &HttpCtx) -> Result<()> {
    let local_ip = stream.local_addr()?.ip();
    let mut conn = H1Conn::new(ctx.limits);
    conn.set_server_name(ctx.server_name.clone());

    let mut buf = [0u8; READ_BUF];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
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
