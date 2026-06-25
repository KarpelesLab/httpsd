---
name: api-positioning
description: How httpsd's consumer API should be shaped — lean low-level core, framework ergonomics behind feature flags
metadata:
  type: feedback
---

When extending httpsd's public API, framework-style ergonomics (routing,
`IntoResponse`, etc.) are wanted, but must be **opt-in behind a Cargo feature**
so the low-level core stays lean and dependency-free. The core `Handler`
(`Fn(&Request) -> Response`) + sans-I/O engine must remain unchanged.

The user declined adopting the `http` crate's types — keep httpsd standalone /
pure-Rust (purecrypto + compcol only).

**Why:** httpsd targets the hyper/tiny_http tier (a foundation), but should be
pleasant for app devs too — without forcing the weight on everyone.

**How to apply:** Add ergonomic layers as default-on, dependency-free features
(e.g. `router`, added 2026-06; gives `Router` + `IntoResponse`, `Request::param`
only exists under `cfg(feature="router")`). Gate any new field on core types by
the feature so feature-off builds have zero footprint.
