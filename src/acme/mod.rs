//! Automatic TLS certificates via ACME (RFC 8555) — Let's Encrypt and any
//! compatible CA.
//!
//! The pieces: [`jose`] (JWS/JWK signing), [`json`] (a small JSON reader for
//! ACME responses), and — added incrementally — the on-disk store, the protocol
//! client over `rsurl`, the challenge solvers, and the issuance manager.

pub mod client;
pub mod jose;
pub mod json;
pub mod manager;
pub mod store;

pub use manager::{AcmeConfig, AcmeManager, CertChoice};
