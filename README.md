# httpsd

A pure-Rust HTTP server (HTTP/1.1, HTTP/2, and HTTP/3) with a **sans-I/O core**
and **pluggable runtimes**.

Use it as a library — drop in your own handler and pick the runtime that fits
(blocking thread pool, [tokio](https://tokio.rs), or [mio](https://github.com/tokio-rs/mio)) —
or as a command-line server that serves a directory or a TOML config file.

- **Sans-I/O protocol core.** [`proto::H1Conn`](src/proto/conn.rs) turns bytes into
  `Request`s and serializes `Response`s back into bytes. It owns no socket, so it
  is trivially testable and reusable across every runtime.
- **HTTP/1.1, HTTP/2, and HTTP/3.** One synchronous [`Handler`](src/handler.rs)
  serves all three. HTTP/2 is negotiated via ALPN on the TLS server; HTTP/3 runs
  over QUIC/UDP.
- **TLS & QUIC via [purecrypto](https://crates.io/crates/purecrypto).** HTTPS is
  built on purecrypto's own sans-I/O TLS 1.2/1.3 engine and HTTP/3 on its QUIC
  stack — no OpenSSL, no C.
- **Compression via [compcol](https://crates.io/crates/compcol).** gzip/deflate
  response compression, plus HPACK (HTTP/2) and QPACK (HTTP/3) header coding.
- **No mandatory async runtime.** The default build is a blocking thread pool;
  tokio and mio are opt-in.

## Quick start (CLI)

```sh
# Serve the current directory over HTTP on 127.0.0.1:8080
httpsd

# Serve a specific directory on a chosen address
httpsd ./public -l 0.0.0.0:8080

# HTTPS with a real certificate
httpsd ./public -l 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem

# HTTPS with an ephemeral self-signed cert (development)
httpsd ./public -l 127.0.0.1:8443 --self-signed

# Also serve HTTP/3 over QUIC/UDP on the same port (requires TLS)
httpsd ./public -l 127.0.0.1:8443 --self-signed --http3

# Run from a config file (see samples/config.toml)
httpsd -c config.toml
```

HTTP/2 is negotiated automatically over HTTPS (ALPN `h2`); clients that don't
support it fall back to HTTP/1.1. HTTP/3 is served on UDP when `--http3` is given.

Run `httpsd --help` for all options.

## Quick start (library)

```rust
use httpsd::{Server, Response, Request};

fn main() -> httpsd::Result<()> {
    Server::bind("127.0.0.1:8080")?
        .handler(|req: &Request| Response::text(format!("you asked for {}", req.path())))
        .run() // blocking thread-pool runtime
}
```

Serve static files:

```rust
use httpsd::Server;

Server::bind("0.0.0.0:8080")?
    .serve_dir("./public")
    .workers(8)
    .run()?;
```

Enable HTTPS:

```rust
use httpsd::{Server, tls::TlsAcceptor};

let acceptor = TlsAcceptor::from_pem_files("cert.pem", "key.pem")?;
Server::bind("0.0.0.0:8443")?
    .serve_dir("./public")
    .tls(acceptor)
    .run()?;
```

### Choosing a runtime

The same `Server` drives any compiled-in runtime:

```rust
server.run()?;             // rt-threadpool: blocking accept loop + worker pool
server.run_tokio().await?; // rt-tokio: one async task per connection
server.run_mio()?;         // rt-mio: single-thread readiness event loop
server.run_h3()?;          // h3: QUIC/UDP event loop (HTTP/3)
```

The TCP runtimes serve HTTP/1.1 and (over TLS) HTTP/2; `run_h3` serves HTTP/3
on UDP. To offer all three, run a TCP runtime and `run_h3` on separate threads
sharing the same [`TlsAcceptor`](src/tls.rs).

A custom handler is just `Fn(&Request) -> Response` (or anything implementing
[`Handler`](src/handler.rs)). Because the core is sans-I/O, one synchronous
handler works identically under all three runtimes.

## Configuration file

```toml
listen = "0.0.0.0:8080"        # or ["127.0.0.1:8080", "[::1]:8080"]
root = "./public"              # document root for static file serving
server_name = "httpsd"
workers = 8

[tls]
cert = "cert.pem"              # PEM chain, leaf first
key  = "key.pem"               # PKCS#8 / PKCS#1 RSA / SEC1 EC
# self_signed = ["localhost"]  # alternatively, generate an ephemeral cert

[compress]
enabled = true
min_size = 256
```

See [`samples/config.toml`](samples/config.toml).

## Feature flags

| Feature         | Default | Description                                              |
|-----------------|:-------:|----------------------------------------------------------|
| `cli`           |   ✓     | The `httpsd` binary (implies `config` + `rt-threadpool`).|
| `rt-threadpool` |   ✓     | Blocking accept loop backed by a worker thread pool.     |
| `tls`           |   ✓     | HTTPS via `purecrypto`.                                  |
| `compress`      |   ✓     | gzip/deflate response compression via `compcol`.         |
| `h2`            |   ✓     | HTTP/2 over TLS (ALPN); HPACK via `compcol`.             |
| `h3`            |         | HTTP/3 over QUIC/UDP; QPACK via `compcol`, QUIC via `purecrypto`. |
| `config`        |         | TOML configuration loading (pulled in by `cli`).         |
| `rt-tokio`      |         | Asynchronous tokio runtime.                              |
| `rt-mio`        |         | Single-thread mio event-loop runtime.                    |

To use httpsd as a lean embeddable library — say, tokio HTTPS without the CLI:

```toml
[dependencies]
httpsd = { version = "0.1", default-features = false, features = ["rt-tokio", "tls", "compress"] }
```

## Capabilities & limits

- HTTP/1.0 and HTTP/1.1 with persistent connections (keep-alive).
- HTTP/2 (RFC 9113) over TLS: HPACK, stream multiplexing, connection and
  per-stream flow control, SETTINGS/WINDOW_UPDATE/PING/RST_STREAM/GOAWAY.
- HTTP/3 (RFC 9114) over QUIC: control + QPACK streams, HEADERS/DATA framing,
  one connection per peer on a single UDP socket.
- Request bodies via `Content-Length` and chunked `Transfer-Encoding`
  (buffered), with configurable size limits.
- `GET`/`HEAD` static file serving with MIME detection, directory `index.html`,
  `ETag`/`Last-Modified` conditional requests, and single-range (`206`) support.
- Path-traversal protection (rejects `..`, canonicalizes against the root).
- Response compression negotiated from `Accept-Encoding`, skipping
  already-compressed media types and tiny bodies.

Verified against `curl` for HTTP/1.1, `--http2`, and `--http3-only`.

Out of scope for this version: streaming request/response bodies, HTTP/2 server
push, QUIC connection migration, and async handler traits (handlers are
synchronous by design). HTTP/3 demultiplexes connections by peer address.

## License

MIT
