//! An ergonomic routing layer (feature `router`).
//!
//! [`Router`] dispatches a request to one of several handlers by HTTP method and
//! path pattern, the way `axum` / `actix-web` users expect:
//!
//! ```
//! use httpsd::{Request, Response, StatusCode};
//! use httpsd::router::Router;
//!
//! let app = Router::new()
//!     .get("/", |_req: &Request| "hello world")
//!     .get("/users/:id", |req: &Request| {
//!         format!("user {}", req.param("id").unwrap_or("?"))
//!     })
//!     .post("/users", |_req: &Request| (StatusCode::CREATED, "created"))
//!     .fallback(|_req: &Request| (StatusCode::NOT_FOUND, "nope"));
//!
//! # let _ = |server: httpsd::rt::Server| -> httpsd::rt::Server {
//! server.handler(app)
//! # };
//! ```
//!
//! A `Router` *is* a [`Handler`], so hand it straight to
//! [`Server::handler`](crate::rt::Server::handler). Route handlers are looser
//! than the bare [`Handler`] trait: they can return anything that implements
//! [`IntoResponse`] — `&str`, `String`, `Vec<u8>`, a [`StatusCode`], a
//! `(StatusCode, T)` pair, an `Option<T>`, or a `Result<T, E>` (so `?` works in
//! a handler) — not just a fully-built [`Response`].
//!
//! Path patterns are split on `/`. A `:name` segment captures one path segment
//! (read it back with [`Request::param`]); a trailing `*name` captures the rest
//! of the path. Everything else matches literally. Leading and trailing slashes
//! are ignored, so `/a/b`, `a/b`, and `/a/b/` all match the pattern `/a/b`.

mod response;

pub use response::IntoResponse;

use crate::handler::Handler;
use crate::proto::{Method, Request, Response, StatusCode};

/// One segment of a compiled route pattern.
enum Seg {
    /// A literal segment that must match exactly.
    Lit(String),
    /// `:name` — captures a single path segment.
    Param(String),
    /// `*name` — captures the remainder of the path (must be the last segment).
    Wildcard(String),
}

/// A route handler: any `Fn(&Request) -> impl IntoResponse`.
///
/// You rarely name this trait; it is implemented automatically for closures and
/// functions you pass to [`Router::get`] and friends.
pub trait RouteHandler: Send + Sync {
    /// Invoke the handler and coerce its return value into a [`Response`].
    fn call(&self, req: &Request) -> Response;
}

impl<F, R> RouteHandler for F
where
    F: Fn(&Request) -> R + Send + Sync,
    R: IntoResponse,
{
    fn call(&self, req: &Request) -> Response {
        (self)(req).into_response()
    }
}

struct Route {
    method: Method,
    segs: Vec<Seg>,
    handler: Box<dyn RouteHandler>,
}

impl Route {
    /// Match the (already-split) request path against this route's pattern,
    /// returning the captured parameters on success (empty `Vec` when the
    /// pattern has none). The caller splits the path once and reuses it across
    /// every route, so matching allocates nothing until a capture is found.
    fn matches(&self, path_segs: &[&str]) -> Option<Vec<(String, String)>> {
        let mut params = Vec::new();
        let mut i = 0;
        for seg in &self.segs {
            match seg {
                Seg::Lit(lit) => {
                    if path_segs.get(i)? != lit {
                        return None;
                    }
                    i += 1;
                }
                Seg::Param(name) => {
                    let value = path_segs.get(i)?;
                    params.push((name.clone(), (*value).to_owned()));
                    i += 1;
                }
                Seg::Wildcard(name) => {
                    // Captures everything left, including nothing.
                    params.push((name.clone(), path_segs[i..].join("/")));
                    return Some(params);
                }
            }
        }
        // A non-wildcard pattern must consume the whole path.
        if i == path_segs.len() {
            Some(params)
        } else {
            None
        }
    }
}

/// A request router: match by method and path, dispatch to a handler.
///
/// See the [module docs](self) for the pattern syntax and an example. Build one
/// with [`Router::new`], add routes with the per-method builders (or the generic
/// [`route`](Router::route)), and optionally set a [`fallback`](Router::fallback)
/// for unmatched paths. The result implements [`Handler`].
#[derive(Default)]
pub struct Router {
    routes: Vec<Route>,
    fallback: Option<Box<dyn RouteHandler>>,
}

impl Router {
    /// An empty router. Without any routes (or a fallback) it answers `404`.
    pub fn new() -> Router {
        Router {
            routes: Vec::new(),
            fallback: None,
        }
    }

    /// Register `handler` for `method` requests matching `pattern`.
    pub fn route<H>(mut self, method: Method, pattern: &str, handler: H) -> Router
    where
        H: RouteHandler + 'static,
    {
        self.routes.push(Route {
            method,
            segs: parse_pattern(pattern),
            handler: Box::new(handler),
        });
        self
    }

    /// Register a `GET` route.
    pub fn get<H: RouteHandler + 'static>(self, pattern: &str, handler: H) -> Router {
        self.route(Method::Get, pattern, handler)
    }

    /// Register a `POST` route.
    pub fn post<H: RouteHandler + 'static>(self, pattern: &str, handler: H) -> Router {
        self.route(Method::Post, pattern, handler)
    }

    /// Register a `PUT` route.
    pub fn put<H: RouteHandler + 'static>(self, pattern: &str, handler: H) -> Router {
        self.route(Method::Put, pattern, handler)
    }

    /// Register a `DELETE` route.
    pub fn delete<H: RouteHandler + 'static>(self, pattern: &str, handler: H) -> Router {
        self.route(Method::Delete, pattern, handler)
    }

    /// Register a `PATCH` route.
    pub fn patch<H: RouteHandler + 'static>(self, pattern: &str, handler: H) -> Router {
        self.route(Method::Patch, pattern, handler)
    }

    /// Register a `HEAD` route.
    pub fn head<H: RouteHandler + 'static>(self, pattern: &str, handler: H) -> Router {
        self.route(Method::Head, pattern, handler)
    }

    /// Register an `OPTIONS` route.
    pub fn options<H: RouteHandler + 'static>(self, pattern: &str, handler: H) -> Router {
        self.route(Method::Options, pattern, handler)
    }

    /// Set the handler invoked when no route matches the path (otherwise `404`).
    pub fn fallback<H: RouteHandler + 'static>(mut self, handler: H) -> Router {
        self.fallback = Some(Box::new(handler));
        self
    }

    /// Match the request and run the chosen handler. Returns `405 Method Not
    /// Allowed` (with an `Allow` header) when the path matches but the method
    /// does not, and otherwise the fallback or a `404`.
    fn dispatch(&self, req: &Request) -> Response {
        let path_segs = segments(req.path());
        let mut allowed: Vec<&str> = Vec::new();
        for route in &self.routes {
            let Some(params) = route.matches(&path_segs) else {
                continue;
            };
            if &route.method != req.method() {
                let token = route.method.as_str();
                if !allowed.contains(&token) {
                    allowed.push(token);
                }
                continue;
            }
            if params.is_empty() {
                return route.handler.call(req);
            }
            // Inject captured params for `Request::param`. Only param/wildcard
            // routes pay for the clone.
            let mut routed = req.clone();
            routed.set_params(params);
            return route.handler.call(&routed);
        }

        if !allowed.is_empty() {
            return Response::status(StatusCode::METHOD_NOT_ALLOWED)
                .header("Allow", allowed.join(", "));
        }
        match &self.fallback {
            Some(handler) => handler.call(req),
            None => Response::status(StatusCode::NOT_FOUND),
        }
    }
}

impl Handler for Router {
    fn handle(&self, req: &Request) -> Response {
        self.dispatch(req)
    }
}

/// Split a path (or pattern) into segments, ignoring leading/trailing slashes.
fn segments(path: &str) -> Vec<&str> {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        Vec::new()
    } else {
        trimmed.split('/').collect()
    }
}

/// Compile a route pattern into segments.
fn parse_pattern(pattern: &str) -> Vec<Seg> {
    segments(pattern)
        .into_iter()
        .map(|seg| {
            if let Some(name) = seg.strip_prefix(':') {
                Seg::Param(name.to_owned())
            } else if let Some(name) = seg.strip_prefix('*') {
                Seg::Wildcard(if name.is_empty() {
                    "*".to_owned()
                } else {
                    name.to_owned()
                })
            } else {
                Seg::Lit(seg.to_owned())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: Method, target: &str) -> Request {
        Request::new(
            method,
            target.to_owned(),
            crate::proto::Version::Http11,
            crate::proto::Headers::new(),
            Vec::new(),
        )
    }

    fn body(resp: &Response) -> String {
        String::from_utf8_lossy(resp.body_ref().as_bytes()).into_owned()
    }

    #[test]
    fn static_route_and_404() {
        let app = Router::new().get("/", |_: &Request| "root");
        assert_eq!(body(&app.handle(&req(Method::Get, "/"))), "root");
        assert_eq!(
            app.handle(&req(Method::Get, "/missing")).status_code(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn path_params_captured() {
        let app = Router::new().get("/users/:id", |r: &Request| {
            format!("id={}", r.param("id").unwrap_or("?"))
        });
        assert_eq!(body(&app.handle(&req(Method::Get, "/users/42"))), "id=42");
        // Trailing slash and extra leading slash both normalize.
        assert_eq!(body(&app.handle(&req(Method::Get, "/users/42/"))), "id=42");
        // Too many segments must not match a fixed pattern.
        assert_eq!(
            app.handle(&req(Method::Get, "/users/42/x")).status_code(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn wildcard_captures_remainder() {
        let app = Router::new().get("/static/*path", |r: &Request| {
            r.param("path").unwrap_or("").to_owned()
        });
        assert_eq!(
            body(&app.handle(&req(Method::Get, "/static/css/app.css"))),
            "css/app.css"
        );
        assert_eq!(body(&app.handle(&req(Method::Get, "/static/"))), "");
    }

    #[test]
    fn method_mismatch_is_405_with_allow() {
        let app = Router::new()
            .get("/x", |_: &Request| "g")
            .post("/x", |_: &Request| "p");
        let resp = app.handle(&req(Method::Delete, "/x"));
        assert_eq!(resp.status_code(), StatusCode::METHOD_NOT_ALLOWED);
        let allow = resp.headers().get("allow").unwrap();
        assert!(allow.contains("GET") && allow.contains("POST"));
    }

    #[test]
    fn query_string_ignored_in_match() {
        let app = Router::new().get("/search", |r: &Request| r.query().unwrap_or("").to_owned());
        assert_eq!(body(&app.handle(&req(Method::Get, "/search?q=hi"))), "q=hi");
    }

    #[test]
    fn fallback_used() {
        let app = Router::new()
            .get("/", |_: &Request| "root")
            .fallback(|_: &Request| (StatusCode::FORBIDDEN, "fb"));
        let resp = app.handle(&req(Method::Get, "/nope"));
        assert_eq!(body(&resp), "fb");
        assert_eq!(resp.status_code(), StatusCode::FORBIDDEN);
    }
}
