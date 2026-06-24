//! The sans-I/O HTTP/1.x protocol core: value types plus the [`H1Conn`] engine.
//!
//! Nothing in this module performs I/O. The types here describe HTTP messages
//! and the [`H1Conn`] state machine turns a byte stream into [`Request`]s and
//! serializes [`Response`]s back into bytes. Runtimes in [`crate::rt`] supply
//! the sockets.

mod conn;
mod headers;
mod method;
mod request;
mod response;
mod status;
mod version;

pub use conn::{H1Conn, Limits};
pub use headers::Headers;
pub use method::Method;
pub use request::Request;
pub use response::{Body, Response};
pub use status::StatusCode;
pub use version::Version;

pub(crate) use conn::http_date;
