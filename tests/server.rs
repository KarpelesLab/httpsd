//! End-to-end tests that exercise the whole stack.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use httpsd::{Response, Server, StatusCode};

/// Grab a free TCP port by binding to :0 and immediately releasing it.
fn free_addr() -> std::net::SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

/// A throwaway directory unique to this test run.
fn temp_dir(tag: &str) -> std::path::PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("httpsd-test-{}-{}-{}", std::process::id(), tag, n));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Connect, retrying briefly while the server thread spins up.
fn connect(addr: std::net::SocketAddr) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => return s,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("could not connect to test server: {e}"),
        }
    }
}

fn request(addr: std::net::SocketAddr, raw: &[u8]) -> Vec<u8> {
    let mut stream = connect(addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(raw).unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    buf
}

#[test]
fn serves_static_file_over_tcp() {
    let dir = temp_dir("static");
    std::fs::write(dir.join("index.html"), "<h1>hello httpsd</h1>").unwrap();

    let addr = free_addr();
    std::thread::spawn(move || {
        Server::bind(addr)
            .unwrap()
            .serve_dir(dir)
            .workers(2)
            .run()
            .unwrap();
    });

    let resp = request(
        addr,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    let text = String::from_utf8_lossy(&resp);
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "status: {text}");
    assert!(text.contains("Content-Type: text/html"), "ct: {text}");
    assert!(text.contains("<h1>hello httpsd</h1>"), "body: {text}");
}

#[test]
fn custom_handler_and_404() {
    let addr = free_addr();
    std::thread::spawn(move || {
        Server::bind(addr)
            .unwrap()
            .handler(|req: &httpsd::Request| {
                if req.path() == "/ping" {
                    Response::text("pong")
                } else {
                    Response::status(StatusCode::NOT_FOUND)
                }
            })
            .workers(1)
            .run()
            .unwrap();
    });

    let ok = String::from_utf8(request(
        addr,
        b"GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    ))
    .unwrap();
    assert!(ok.contains("200 OK"));
    assert!(ok.trim_end().ends_with("pong"));

    let missing = String::from_utf8(request(
        addr,
        b"GET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    ))
    .unwrap();
    assert!(missing.contains("404 Not Found"));
}

#[test]
fn keep_alive_two_requests_one_connection() {
    let addr = free_addr();
    std::thread::spawn(move || {
        Server::bind(addr)
            .unwrap()
            .handler(|_: &httpsd::Request| Response::text("ok"))
            .workers(1)
            .run()
            .unwrap();
    });

    let mut stream = connect(addr);
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    // First request keeps the connection alive.
    stream
        .write_all(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    // Second request closes it.
    stream
        .write_all(b"GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf);
    // Two responses on the one connection.
    assert_eq!(text.matches("HTTP/1.1 200 OK").count(), 2, "got: {text}");
}

/// Split a raw HTTP response into (head, body).
fn split_response(raw: &[u8]) -> (String, &[u8]) {
    let split = find(raw, b"\r\n\r\n").expect("headers end") + 4;
    (
        String::from_utf8_lossy(&raw[..split]).into_owned(),
        &raw[split..],
    )
}

#[test]
fn streams_large_file_byte_exact_over_blocking_runtime() {
    let dir = temp_dir("bigfile");
    // Larger than the 64 KiB stream chunk, so it is served across many chunks.
    let data: Vec<u8> = (0..(300 * 1024)).map(|i| (i % 256) as u8).collect();
    std::fs::write(dir.join("big.bin"), &data).unwrap();

    let addr = free_addr();
    std::thread::spawn(move || {
        Server::bind(addr)
            .unwrap()
            .serve_dir(dir)
            .workers(2)
            .run()
            .unwrap();
    });

    let raw = request(
        addr,
        b"GET /big.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let (head, body) = split_response(&raw);
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "head: {head}");
    assert!(
        head.contains(&format!("Content-Length: {}\r\n", data.len())),
        "head: {head}"
    );
    assert_eq!(body.len(), data.len(), "body length mismatch");
    assert_eq!(body, &data[..], "streamed file must be byte-for-byte exact");
}

#[test]
fn range_request_streams_exact_span() {
    let dir = temp_dir("rangefile");
    let data: Vec<u8> = (0..(200 * 1024)).map(|i| (i % 256) as u8).collect();
    std::fs::write(dir.join("data.bin"), &data).unwrap();

    let addr = free_addr();
    std::thread::spawn(move || {
        Server::bind(addr)
            .unwrap()
            .serve_dir(dir)
            .workers(2)
            .run()
            .unwrap();
    });

    // Span crosses a chunk boundary.
    let (start, end) = (1234usize, 1234 + 64 * 1024 + 9);
    let raw = request(
        addr,
        format!(
            "GET /data.bin HTTP/1.1\r\nHost: x\r\nRange: bytes={start}-{end}\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    );
    let (head, body) = split_response(&raw);
    assert!(head.starts_with("HTTP/1.1 206"), "head: {head}");
    assert!(
        head.contains(&format!(
            "Content-Range: bytes {start}-{end}/{}\r\n",
            data.len()
        )),
        "head: {head}"
    );
    assert_eq!(
        body,
        &data[start..=end],
        "range body must be the exact span"
    );
}

#[test]
fn head_on_file_sends_length_no_body() {
    let dir = temp_dir("headfile");
    let data = vec![42u8; 256 * 1024];
    std::fs::write(dir.join("f.bin"), &data).unwrap();

    let addr = free_addr();
    std::thread::spawn(move || {
        Server::bind(addr)
            .unwrap()
            .serve_dir(dir)
            .workers(1)
            .run()
            .unwrap();
    });

    let raw = request(
        addr,
        b"HEAD /f.bin HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    );
    let (head, body) = split_response(&raw);
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "head: {head}");
    assert!(
        head.contains(&format!("Content-Length: {}\r\n", data.len())),
        "head: {head}"
    );
    assert!(
        body.is_empty(),
        "HEAD must not send a body, got {} bytes",
        body.len()
    );
}

#[cfg(feature = "compress")]
#[test]
fn file_body_is_not_compressed() {
    let dir = temp_dir("nocompress");
    // Highly compressible and well over the compression min-size, but a file
    // body must stream through untouched (no Content-Encoding).
    let data = vec![b'a'; 128 * 1024];
    std::fs::write(dir.join("a.txt"), &data).unwrap();

    let addr = free_addr();
    std::thread::spawn(move || {
        Server::bind(addr)
            .unwrap()
            .serve_dir(dir)
            .workers(1)
            .run()
            .unwrap();
    });

    let raw = request(
        addr,
        b"GET /a.txt HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    let (head, body) = split_response(&raw);
    assert!(
        !head.to_ascii_lowercase().contains("content-encoding"),
        "file body must not be compressed: {head}"
    );
    assert_eq!(body, &data[..], "uncompressed body must be byte-exact");
}

#[cfg(feature = "compress")]
#[test]
fn gzip_compression_round_trip() {
    use compcol::gzip::Gzip;

    let body = "abcdefgh".repeat(2048); // 16 KiB, very compressible
    let body_for_server = body.clone();
    let addr = free_addr();
    std::thread::spawn(move || {
        Server::bind(addr)
            .unwrap()
            .handler(move |_: &httpsd::Request| {
                Response::new(StatusCode::OK)
                    .header("Content-Type", "text/plain")
                    .body(body_for_server.clone())
            })
            .workers(1)
            .run()
            .unwrap();
    });

    let raw = request(
        addr,
        b"GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n",
    );
    let split = find(&raw, b"\r\n\r\n").expect("headers end") + 4;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    assert!(head.contains("Content-Encoding: gzip"), "head: {head}");
    assert!(head.contains("Vary: Accept-Encoding"), "head: {head}");

    let decoded = compcol::vec::decompress_to_vec::<Gzip>(&raw[split..]).expect("gunzip");
    assert_eq!(decoded, body.as_bytes());
}

#[cfg(feature = "tls")]
#[test]
fn tls_handshake_and_request_in_process() {
    use std::sync::Arc;

    use httpsd::session::{Session, SessionConfig};
    use httpsd::tls::TlsAcceptor;
    use purecrypto::rng::OsRng;
    use purecrypto::tls::{Config, Connection};

    // Server side: a self-signed identity + an HTTP handler, wrapped in a TLS session.
    let acceptor = TlsAcceptor::self_signed(&["localhost"]).unwrap();
    let cfg = SessionConfig::new(Arc::new(|_: &httpsd::Request| {
        Response::text("secure hello")
    }));
    let mut server = Session::tls(cfg, acceptor.accept().unwrap());

    // Client side: a purecrypto TLS client that trusts anything (test only).
    let client_cfg = Config::builder()
        .rng(Arc::new(OsRng))
        .tls_only()
        .verify_certificates(false)
        .server_name("localhost")
        .build();
    let mut client = Connection::client(&client_cfg).unwrap();

    // Drive the handshake by shuttling records between the two ends.
    for _ in 0..32 {
        let to_server = client.pop().unwrap_or_default();
        if !to_server.is_empty() {
            server.received(&to_server).unwrap();
        }
        let to_client = server.to_send().unwrap();
        if !to_client.is_empty() {
            client.feed(&to_client).unwrap();
        }
        if client.is_handshake_complete() && !server.handshaking() {
            break;
        }
    }
    assert!(
        client.is_handshake_complete(),
        "client handshake incomplete"
    );

    // Application data: send an HTTP request through the tunnel.
    client
        .send(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let req_wire = client.pop().unwrap();
    server.received(&req_wire).unwrap();
    let resp_wire = server.to_send().unwrap();
    client.feed(&resp_wire).unwrap();

    let mut plaintext = Vec::new();
    loop {
        let chunk = client.recv().unwrap_or_default();
        if chunk.is_empty() {
            break;
        }
        plaintext.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&plaintext);
    assert!(text.contains("200 OK"), "decrypted: {text}");
    assert!(text.contains("secure hello"), "decrypted: {text}");
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
