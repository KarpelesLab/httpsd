//! Asynchronous runtime driver, built on tokio.
//!
//! Each accepted connection becomes a tokio task. The sans-I/O [`Session`] does
//! all protocol work synchronously inside the task; tokio only provides the
//! async socket reads and writes. This reuses the exact same engine, TLS, and
//! compression code paths as the blocking runtimes.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::error::{Error, Result};
use crate::rt::common::READ_BUF;
use crate::session::{Session, SessionConfig};

#[cfg(feature = "tls")]
use crate::tls::TlsAcceptor;

struct Shared {
    cfg: SessionConfig,
    #[cfg(feature = "tls")]
    tls: Option<TlsAcceptor>,
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
    });

    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let outcome = serve(stream, shared).await;
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

async fn serve(mut stream: TcpStream, shared: Arc<Shared>) -> Result<()> {
    stream.set_nodelay(true).ok();
    let mut session = build_session(&shared)?;

    let mut buf = vec![0u8; READ_BUF];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
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
