# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/KarpelesLab/httpsd/compare/v0.1.0...v0.1.1) - 2026-06-30

### Fixed

- *(h3)* reclaim and cap request-stream state (MEDIUM)
- *(quic)* bound connection table against spoofed-source flood (HIGH)

### Other

- Keep Body an opaque struct to preserve the public API (semver)
- don't stream a body in response to HEAD
- Serve static files as streaming bodies; keep File bodies uncompressed
- Stream HTTP/3 file bodies as QUIC send capacity allows
- Stream HTTP/2 file bodies under flow control without buffering
- Stream HTTP/1 file bodies in bounded chunks across all runtimes
- Add file-backed streaming Body with positioned reads
- CLI + config: privdrop orchestration and Server header control
- Add privilege-drop core + bind-readiness handshake
- Fix O(n²) DoS in HTTP/1 parser (incremental header scan + chunked decode)
- *(threadpool)* avoid unused_mut warning when acme feature is off
- harden private-key handling (audit LOW findings)
- Fix static-file security findings: dotfiles, range reads, nosniff, gzip on 206
- *(gdns)* strip control chars from redirect Location (defense in depth)
- *(mio)* cap connection map and reap idle / slow-trickle peers
- *(tokio)* add connection cap and read/handshake timeouts
- *(threadpool)* bound slow-trickle slowloris and fix ACME 1-worker deadlock
- *(manager)* bound issuance state and add negative caching
- *(json)* cap parse recursion depth and input length
- *(jose)* validate SEC1 point in xy() instead of panicking
- enforce per-connection resource limits (security hardening)
- Fix HTTP/1.x parser/serializer security findings in conn.rs
- Include acme in the cli feature so the default binary can issue certs
- Harden the thread-pool runtime against connection-exhaustion DoS
- Back off and rate-limit on accept() errors to prevent EMFILE busy-loop
- drop redundant plain-transport copies and per-route path splits
- Add http-crate interop behind the `http` feature
- Add ergonomic routing layer behind the `router` feature
- Format h2 response_fields (rustfmt)
- Fix CI: move h2 response_fields before its test module; qualify TlsStream doc link
