//! End-to-end tests for the features an application server (SAPI) needs:
//! connection info in the handler, streamed response bodies, custom reason
//! phrases and byte-valued headers. Each streaming test runs on every runtime
//! compiled in.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use httpsd::{Body, Request, Response, Server, StatusCode};

/// A port for a test server. Ports are handed out sequentially from a
/// per-process base below the OS ephemeral range (32768+ on Linux), so neither
/// parallel tests nor client sockets can grab the same one between the check
/// and the server's bind.
fn free_addr() -> SocketAddr {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let _ = NEXT.compare_exchange(
        0,
        10_000 + (std::process::id() % 400) as u16 * 50,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    loop {
        let port = NEXT.fetch_add(1, Ordering::Relaxed);
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        // Skip ports something else already holds.
        if TcpListener::bind(addr).is_ok() {
            return addr;
        }
    }
}

fn connect(addr: SocketAddr) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => {
                s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                return s;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("could not connect to test server: {e}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Rt {
    #[cfg(feature = "rt-threadpool")]
    Pool,
    #[cfg(feature = "rt-tokio")]
    Tokio,
    #[cfg(feature = "rt-mio")]
    Mio,
}

fn runtimes() -> Vec<Rt> {
    vec![
        #[cfg(feature = "rt-threadpool")]
        Rt::Pool,
        #[cfg(feature = "rt-tokio")]
        Rt::Tokio,
        #[cfg(feature = "rt-mio")]
        Rt::Mio,
    ]
}

/// Start a server with `handler` on the given runtime; returns its address.
fn start<H: httpsd::Handler + 'static>(rt: Rt, handler: H) -> SocketAddr {
    let addr = free_addr();
    let server = Server::bind(addr).unwrap().handler(handler).workers(2);
    std::thread::spawn(move || match rt {
        #[cfg(feature = "rt-threadpool")]
        Rt::Pool => server.run().unwrap(),
        #[cfg(feature = "rt-tokio")]
        Rt::Tokio => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(server.run_tokio())
            .unwrap(),
        #[cfg(feature = "rt-mio")]
        Rt::Mio => server.run_mio().unwrap(),
    });
    addr
}

/// Read from `s` until `buf` contains `needle`.
fn read_until(s: &mut TcpStream, buf: &mut Vec<u8>, needle: &[u8]) {
    let mut tmp = [0u8; 4096];
    while find(buf, needle).is_none() {
        let n = s.read(&mut tmp).expect("read timed out waiting for data");
        assert!(
            n > 0,
            "connection closed early; got {:?}",
            String::from_utf8_lossy(buf)
        );
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// A handler whose body sends "first", waits for the test to release a gate,
/// then sends "second" and finishes.
fn gated_stream() -> (impl httpsd::Handler, mpsc::Sender<()>) {
    let (gate_tx, gate_rx) = mpsc::channel::<()>();
    let gate_rx = Arc::new(Mutex::new(gate_rx));
    let handler = move |_: &Request| {
        let (tx, body) = Body::channel();
        let gate = Arc::clone(&gate_rx);
        std::thread::spawn(move || {
            tx.send("first").unwrap();
            let _ = gate.lock().unwrap().recv_timeout(Duration::from_secs(5));
            tx.send("second").unwrap();
        });
        Response::new(StatusCode::OK)
            .header("Content-Type", "text/plain")
            .body(body)
    };
    (handler, gate_tx)
}

#[test]
fn stream_body_is_sent_incrementally_and_chunked() {
    for rt in runtimes() {
        let (handler, gate) = gated_stream();
        let addr = start(rt, handler);
        let mut s = connect(addr);
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();

        // "first" must arrive while the producer is still blocked on the gate.
        let mut buf = Vec::new();
        read_until(&mut s, &mut buf, b"5\r\nfirst\r\n");
        let head = String::from_utf8_lossy(&buf).to_string();
        assert!(
            head.contains("Transfer-Encoding: chunked\r\n"),
            "{rt:?}: {head}"
        );
        assert!(!head.contains("Content-Length"), "{rt:?}: {head}");

        gate.send(()).unwrap();
        read_until(&mut s, &mut buf, b"6\r\nsecond\r\n0\r\n\r\n");

        // Keep-alive survives: a second request on the same connection works.
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        gate.send(()).unwrap();
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).unwrap();
        assert!(find(&rest, b"0\r\n\r\n").is_some(), "{rt:?}");
    }
}

#[test]
fn stream_body_on_http10_is_close_delimited() {
    for rt in runtimes() {
        let (handler, gate) = gated_stream();
        let addr = start(rt, handler);
        let mut s = connect(addr);
        s.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        gate.send(()).unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.ends_with("\r\n\r\nfirstsecond"), "{rt:?}: {text}");
        assert!(!text.contains("chunked"), "{rt:?}: {text}");
    }
}

#[test]
fn producer_sees_client_disconnect() {
    for rt in runtimes() {
        let (closed_tx, closed_rx) = mpsc::channel::<bool>();
        let closed_tx = Mutex::new(closed_tx);
        let addr = start(rt, move |_: &Request| {
            let (tx, body) = Body::channel();
            let report = closed_tx.lock().unwrap().clone();
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                // Keep writing until the client is gone (or give up).
                while Instant::now() < deadline {
                    if tx.send(vec![b'x'; 1024]).is_err() {
                        let _ = report.send(tx.is_closed());
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                let _ = report.send(false);
            });
            Response::new(StatusCode::OK).body(body)
        });

        let mut s = connect(addr);
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        read_until(&mut s, &mut buf, b"\r\n\r\n");
        drop(s);
        let saw_close = closed_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("producer never finished");
        assert!(saw_close, "{rt:?}: producer did not see the disconnect");
    }
}

#[test]
fn handler_sees_connection_info() {
    for rt in runtimes() {
        let addr = start(rt, |req: &Request| {
            Response::text(format!(
                "peer={} local={} secure={}",
                req.peer_addr().map(|a| a.to_string()).unwrap_or_default(),
                req.local_addr().map(|a| a.to_string()).unwrap_or_default(),
                req.is_secure(),
            ))
        });
        let mut s = connect(addr);
        let client = s.local_addr().unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8_lossy(&buf);
        let want = format!("peer={client} local={addr} secure=false");
        assert!(text.ends_with(&want), "{rt:?}: {text}");
    }
}

#[test]
fn custom_reason_and_raw_header_bytes_reach_the_client() {
    for rt in runtimes() {
        let addr = start(rt, |req: &Request| {
            let mut resp = Response::new(StatusCode::from(299)).with_reason("My Reason");
            // Echo the raw (Latin-1) request header back, byte for byte.
            let name = req.headers().get_bytes("x-name").unwrap_or(b"").to_vec();
            let mut cd = b"attachment; filename=\"".to_vec();
            cd.extend_from_slice(&name);
            cd.push(b'"');
            resp.headers_mut().append_bytes("Content-Disposition", cd);
            resp
        });
        let mut s = connect(addr);
        s.write_all(
            b"GET / HTTP/1.1\r\nHost: x\r\nX-Name: caf\xe9.txt\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        assert!(buf.starts_with(b"HTTP/1.1 299 My Reason\r\n"), "{rt:?}");
        assert!(
            find(
                &buf,
                b"Content-Disposition: attachment; filename=\"caf\xe9.txt\"\r\n"
            )
            .is_some(),
            "{rt:?}: {}",
            String::from_utf8_lossy(&buf)
        );
    }
}

#[test]
fn public_file_body_streams_a_handler_opened_file() {
    let path = std::env::temp_dir().join(format!("httpsd-sapi-file-{}", std::process::id()));
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &data).unwrap();
    for rt in runtimes() {
        let p = path.clone();
        let addr = start(rt, move |_: &Request| {
            let file = std::fs::File::open(&p).unwrap();
            Response::new(StatusCode::OK).body(Body::from_file(file).unwrap())
        });
        let mut s = connect(addr);
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).unwrap();
        let split = find(&buf, b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&buf[split..], &data[..], "{rt:?}");
    }
    let _ = std::fs::remove_file(&path);
}
