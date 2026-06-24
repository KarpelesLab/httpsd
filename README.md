# httpsd

A pure-Rust HTTP/1.x server with a **sans-I/O core** and **pluggable runtimes**.

Use it as a library — drop in your own handler and pick the runtime that fits
(blocking thread pool, [tokio](https://tokio.rs), or [mio](https://github.com/tokio-rs/mio)) —
or as a command-line server that serves a directory or a TOML config file.

- **Sans-I/O protocol core.** [`proto::H1Conn`](src/proto/conn.rs) turns bytes into
  `Request`s and serializes `Response`s back into bytes. It owns no socket, so it
  is trivially testable and reusable across every runtime.
- **TLS via [purecrypto](https://crates.io/crates/purecrypto).** HTTPS is built on
  purecrypto's own sans-I/O TLS 1.2/1.3 engine — no OpenSSL, no C.
- **Compression via [compcol](https://crates.io/crates/compcol).** Responses are
  gzip/deflate-compressed when the client asks for it.
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

# Run from a config file (see samples/config.toml)
httpsd -c config.toml
```

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
```

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
- Request bodies via `Content-Length` and chunked `Transfer-Encoding`
  (buffered), with configurable size limits.
- `GET`/`HEAD` static file serving with MIME detection, directory `index.html`,
  `ETag`/`Last-Modified` conditional requests, and single-range (`206`) support.
- Path-traversal protection (rejects `..`, canonicalizes against the root).
- Response compression negotiated from `Accept-Encoding`, skipping
  already-compressed media types and tiny bodies.

Out of scope for this version: HTTP/2 and HTTP/3, streaming request/response
bodies, and async handler traits (handlers are synchronous by design).

## License

MIT
