//! The request handler abstraction.

use crate::proto::{Request, Response};

/// Turns a [`Request`] into a [`Response`].
///
/// The trait is deliberately **synchronous**: the engine is sans-I/O and every
/// runtime (thread pool, tokio, mio) calls the handler the same way, so a
/// single handler implementation works everywhere. Handlers must be `Send +
/// Sync` because they are shared across worker threads / tasks.
pub trait Handler: Send + Sync {
    /// Handle one request and produce the response to send back.
    fn handle(&self, req: &Request) -> Response;
}

/// Any `Fn(&Request) -> Response` is a handler.
impl<F> Handler for F
where
    F: Fn(&Request) -> Response + Send + Sync,
{
    fn handle(&self, req: &Request) -> Response {
        (self)(req)
    }
}
