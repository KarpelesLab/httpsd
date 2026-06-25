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

The user DID want `http`-crate interop — but as an opt-in feature so it can be
disabled (don't replace httpsd's own core types; keep the default build
dependency-free of `http`). Added 2026-06 as the non-default `http` feature
(`src/interop.rs`): `From`/`TryFrom` between httpsd and `http` types,
`HttpConvertError`, and `IntoResponse for http::Response` when `router` is on.
(Earlier I mis-recorded this as "declined" — it was accepted, gated.)

**Why:** httpsd targets the hyper/tiny_http tier (a foundation), but should be
pleasant for app devs too — without forcing the weight on everyone.

**How to apply:** Add ergonomic layers as features. Dependency-free ones can be
default-on (e.g. `router`, gives `Router` + `IntoResponse`; `Request::param`
only exists under `cfg(feature="router")`). Ones that pull a dependency stay
opt-in/non-default (e.g. `http`). Gate any new field on core types by the
feature so feature-off builds have zero footprint.
