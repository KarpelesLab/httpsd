//! The plain-HTTP listener: serves ACME HTTP-01 challenges and, by default,
//! redirects everything else to HTTPS (the reason this server is `httpsd`).
//! With `allow_http` it serves content over HTTP instead of redirecting.

use std::net::{IpAddr, TcpStream};
use std::sync::Arc;

use crate::error::Result;
use crate::handler::Handler;
use crate::net::gdns;
use crate::proto::{Limits, Request, Response, StatusCode};
use crate::rt::common::serve_blocking;
use crate::session::{Session, SessionConfig};

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

/// The per-connection handler: ACME challenge, content, or redirect.
struct HttpHandler {
    ctx: Arc<HttpCtx>,
    local_ip: IpAddr,
}

impl Handler for HttpHandler {
    fn handle(&self, req: &Request) -> Response {
        respond(req, self.local_ip, &self.ctx)
    }
}

/// Serve one plain-HTTP connection through the same blocking [`Session`] loop
/// as the main listener (slowloris guard, file and stream bodies, pipelining).
pub(crate) fn serve(stream: &mut TcpStream, ctx: &Arc<HttpCtx>) -> Result<()> {
    let local_ip = stream.local_addr()?.ip();
    let cfg = SessionConfig {
        handler: Arc::new(HttpHandler {
            ctx: Arc::clone(ctx),
            local_ip,
        }),
        limits: ctx.limits,
        server_name: ctx.server_name.clone(),
        hsts: None,
        alt_svc: None,
        #[cfg(feature = "compress")]
        compression: ctx.compression,
    };
    let mut session = Session::plain(cfg);
    serve_blocking(stream, &mut session)
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
        // (Compression is applied by the session.)
        return handler.handle(req);
    }

    // Otherwise upgrade to HTTPS (308 keeps the method/body).
    let location = gdns::redirect_location(req.host(), local_ip, req.target());
    Response::redirect(StatusCode::PERMANENT_REDIRECT, location)
}
