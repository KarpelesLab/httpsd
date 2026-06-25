//! Networking helpers that sit beside the protocol engines: the g-dns redirect
//! scheme and (for ACME) ClientHello inspection.

pub mod gdns;

#[cfg(feature = "acme")]
pub mod clienthello;
