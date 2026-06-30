//! Asynchronous runtime driver, built on tokio.
//!
//! Each accepted connection becomes a tokio task. The sans-I/O [`Session`] does
//! all protocol work synchronously inside the task; tokio only provides the
//! async socket reads and writes. This reuses the exact same engine, TLS, and
//! compression code paths as the blocking runtimes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{Error, Result};
use crate::rt::common::{IO_TIMEOUT, MIN_PROGRESS, READ_BUF};
use crate::session::{Session, SessionConfig};

#[cfg(feature = "tls")]
use crate::tls::TlsAcceptor;

/// Global ceiling on connections served concurrently. Every accept spawns an
/// unbounded task otherwise, so a connection flood can exhaust memory and file
/// descriptors. The cap is a generous safety ceiling (well clear of normal
/// concurrency); excess connections are shed by dropping them immediately so the
/// kernel backlog absorbs and ultimately rejects the burst.
const MAX_INFLIGHT: usize = 8192;

struct Shared {
    cfg: SessionConfig,
    #[cfg(feature = "tls")]
    tls: Option<TlsAcceptor>,
    /// Number of connections currently being served (gated by [`MAX_INFLIGHT`]).
    inflight: AtomicUsize,
}

/// Bind and serve on a tokio runtime until a fatal listener error.
pub(crate) async fn run(
    addrs: Vec<SocketAddr>,
    cfg: SessionConfig,
    #[cfg(feature = "tls")] tls: Option<TlsAcceptor>,
) -> Result<()> {
    let listener = bind_first(&addrs).await?;
    let shared = Arc::new(Shared {
        cfg,
        #[cfg(feature = "tls")]
        tls,
        inflight: AtomicUsize::new(0),
    });

    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                // Shed load past the global cap by dropping the connection.
                if shared.inflight.fetch_add(1, Ordering::Relaxed) >= MAX_INFLIGHT {
                    shared.inflight.fetch_sub(1, Ordering::Relaxed);
                    drop(stream);
                    continue;
                }
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let outcome = serve(stream, &shared).await;
                    shared.inflight.fetch_sub(1, Ordering::Relaxed);
                    if cfg!(debug_assertions)
                        && let Err(e) = outcome
                    {
                        eprintln!("httpsd: connection ended: {e}");
                    }
                });
            }
            Err(e) => {
                if crate::rt::common::note_accept_error("accept error", &e) {
                    tokio::time::sleep(crate::rt::common::ACCEPT_BACKOFF).await;
                }
            }
        }
    }
}

async fn bind_first(addrs: &[SocketAddr]) -> Result<TcpListener> {
    let mut last = None;
    for addr in addrs {
        match TcpListener::bind(addr).await {
            Ok(l) => return Ok(l),
            Err(e) => last = Some(e),
        }
    }
    Err(last
        .map(Error::Io)
        .unwrap_or_else(|| Error::Config("no listen address".into())))
}

async fn serve(mut stream: TcpStream, shared: &Shared) -> Result<()> {
    stream.set_nodelay(true).ok();
    let mut session = build_session(shared)?;

    let mut buf = vec![0u8; READ_BUF];
    // Minimum-throughput deadline (the async analogue of the blocking runtime's
    // rule, see `common::MIN_PROGRESS`): every read is bounded by the time left
    // in the current window, and the window only resets once the peer delivers
    // `MIN_PROGRESS` bytes. A read that elapses without meeting the floor — a
    // fully idle peer or a slow-trickle slowloris — closes the connection. This
    // covers the TLS handshake, the request head, and bodies uniformly.
    let mut window_deadline = Instant::now() + IO_TIMEOUT;
    let mut window_bytes: usize = 0;
    loop {
        let remaining = window_deadline.saturating_duration_since(Instant::now());
        let n = match tokio::time::timeout(remaining, stream.read(&mut buf)).await {
            Ok(r) => r?,
            // Window expired without the peer meeting the throughput floor (it is
            // reset to zero the instant the floor is met below): idle or trickle.
            Err(_elapsed) => break,
        };
        if n == 0 {
            break;
        }
        window_bytes = window_bytes.saturating_add(n);
        if window_bytes >= MIN_PROGRESS {
            window_deadline = Instant::now() + IO_TIMEOUT;
            window_bytes = 0;
        }
        session.received(&buf[..n])?;
        let out = session.to_send()?;
        if !out.is_empty() {
            stream.write_all(&out).await?;
            stream.flush().await?;
        }
        if session.wants_close() {
            break;
        }
    }
    Ok(())
}

fn build_session(shared: &Shared) -> Result<Session> {
    #[cfg(feature = "tls")]
    if let Some(acceptor) = &shared.tls {
        return Ok(Session::tls(shared.cfg.clone(), acceptor.accept()?));
    }
    Ok(Session::plain(shared.cfg.clone()))
}
