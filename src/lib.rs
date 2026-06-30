//! # httpsd
//!
//! A pure-Rust HTTP/1.x server with a **sans-I/O core** and **pluggable
//! runtimes**. The protocol engine ([`proto::H1Conn`]) performs no I/O at all —
//! it turns bytes into [`Request`]s and serializes [`Response`]s back into
//! bytes. Runtimes in [`rt`] move those bytes over real sockets; TLS (via
//! [`purecrypto`](https://docs.rs/purecrypto)) and response compression (via
//! [`compcol`](https://docs.rs/compcol)) are independent layers you can enable
//! with Cargo features.
//!
//! ## As a library
//!
//! ```no_run
//! use httpsd::{Server, Response};
//!
//! # #[cfg(feature = "rt-threadpool")]
//! # fn main() -> httpsd::Result<()> {
//! let server = Server::bind("127.0.0.1:8080")?
//!     .handler(|req: &httpsd::Request| Response::text(format!("you asked for {}", req.path())));
//! server.run()?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "rt-threadpool"))]
//! # fn main() {}
//! ```
//!
//! ## Feature flags
//!
//! - `tls` — HTTPS via `purecrypto`'s sans-I/O TLS engine.
//! - `compress` — gzip/deflate/zlib response compression via `compcol`.
//! - `router` — a [`Router`] with method/path matching plus the
//!   [`IntoResponse`] trait (dependency-free).
//! - `http` — `From`/`TryFrom` interop with the [`http`](https://docs.rs/http)
//!   crate's `Request`/`Response`/`Method`/`StatusCode`/`Headers` types.
//! - `config` — load a [`ServerConfig`] from a TOML file.
//! - `cli` — build the `httpsd` binary.
//! - `rt-threadpool` (default), `rt-tokio`, `rt-mio` — runtime drivers.

// The crate is unsafe-free except for the optional `privdrop` module, whose
// privilege-dropping syscalls (setuid/setgid/chroot via libc) require `unsafe`.
// When that feature is off we keep the hard `forbid`; when it is on we downgrade
// to `deny` so the single module can opt back in with a scoped `allow`.
#![cfg_attr(not(feature = "privdrop"), forbid(unsafe_code))]
#![cfg_attr(feature = "privdrop", deny(unsafe_code))]
#![warn(missing_docs)]

pub mod error;
pub mod handler;
pub mod mime;
pub mod net;
pub mod proto;
pub mod static_files;

#[cfg(feature = "compress")]
pub mod compress;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "h2")]
pub mod h2;

#[cfg(feature = "h3")]
pub mod h3;

#[cfg(feature = "acme")]
pub mod acme;

#[cfg(feature = "router")]
pub mod router;

#[cfg(feature = "http")]
pub mod interop;

pub mod session;

#[cfg(feature = "config")]
pub mod config;

pub mod rt;

#[cfg(feature = "privdrop")]
pub mod privdrop;

pub use error::{Error, Result};
pub use handler::Handler;
pub use proto::{Body, Headers, Method, Request, Response, StatusCode, Version};
pub use session::Session;
pub use static_files::StaticFiles;

#[cfg(feature = "router")]
pub use router::{IntoResponse, Router};

#[cfg(feature = "config")]
pub use config::ServerConfig;

#[cfg(any(feature = "rt-threadpool", feature = "rt-tokio", feature = "rt-mio"))]
pub use rt::Server;
