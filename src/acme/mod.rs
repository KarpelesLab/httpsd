//! Automatic TLS certificates via ACME (RFC 8555) — Let's Encrypt and any
//! compatible CA.
//!
//! The pieces: [`jose`] (JWS/JWK signing), [`json`] (a small JSON reader for
//! ACME responses), and — added incrementally — the on-disk store, the protocol
//! client over `rsurl`, the challenge solvers, and the issuance manager.

// Some helpers here are consumed by the protocol client and manager that land
// in following commits; allow until the module is fully wired.
#![allow(dead_code)]

pub mod jose;
pub mod json;
