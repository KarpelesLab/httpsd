//! Blocking runtime backed by a fixed pool of worker threads.
//!
//! The accept loop runs on the calling thread and hands each accepted socket to
//! a bounded set of worker threads over a channel. With one worker the server
//! is effectively single-threaded; with N workers up to N connections are
//! served concurrently. There is no async runtime involved.

use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::error::Result;
use crate::rt::common::serve_blocking;
use crate::rt::redirect::{self, HttpCtx};
use crate::rt::TlsMode;
use crate::session::{Session, SessionConfig};

#[cfg(feature = "acme")]
use crate::{acme::CertChoice, rt::route};

/// Shared, immutable per-server context handed to each worker.
struct Shared {
    cfg: SessionConfig,
    tls: TlsMode,
}

/// Run a blocking accept loop, dispatching connections to `workers` threads.
pub(crate) fn run(
    listener: TcpListener,
    cfg: SessionConfig,
    tls: TlsMode,
    workers: usize,
) -> Result<()> {
    let shared = Arc::new(Shared { cfg, tls });
    let workers = workers.max(1);
    let (tx, rx): (Sender<TcpStream>, Receiver<TcpStream>) = std::sync::mpsc::channel();
    let rx = Arc::new(Mutex::new(rx));

    for _ in 0..workers {
        let rx = Arc::clone(&rx);
        let shared = Arc::clone(&shared);
        thread::spawn(move || worker_loop(rx, shared));
    }

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if tx.send(stream).is_err() {
                    break;
                }
            }
            Err(e) => eprintln!("httpsd: accept error: {e}"),
        }
    }
    Ok(())
}

fn worker_loop(rx: Arc<Mutex<Receiver<TcpStream>>>, shared: Arc<Shared>) {
    loop {
        let stream = {
            let guard = match rx.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.recv()
        };
        let Ok(stream) = stream else {
            return;
        };
        if let Err(e) = handle(stream, &shared)
            && cfg!(debug_assertions) {
                eprintln!("httpsd: connection ended: {e}");
            }
    }
}

fn handle(mut stream: TcpStream, shared: &Shared) -> Result<()> {
    stream.set_nodelay(true).ok();

    match &shared.tls {
        TlsMode::Plain => {
            let mut session = Session::plain(shared.cfg.clone());
            serve_blocking(&mut stream, &mut session)
        }
        #[cfg(feature = "tls")]
        TlsMode::Static(acceptor) => {
            let tls = acceptor.accept()?;
            let mut session = Session::tls(shared.cfg.clone(), tls);
            serve_blocking(&mut stream, &mut session)
        }
        #[cfg(feature = "acme")]
        TlsMode::Acme(mgr) => handle_acme(stream, shared, mgr),
    }
}

#[cfg(feature = "acme")]
fn handle_acme(mut stream: TcpStream, shared: &Shared, mgr: &crate::acme::AcmeManager) -> Result<()> {
    // Peek the ClientHello, then choose a certificate by SNI/ALPN.
    let Some((initial, info)) = route::read_client_hello(&mut stream)? else {
        return Ok(()); // not TLS / closed early
    };
    let loopback = stream
        .peer_addr()
        .map(|a| a.ip().is_loopback())
        .unwrap_or(false);

    let acceptor = match route::choose(mgr, &info, loopback) {
        CertChoice::Serve(acceptor) => acceptor,
        CertChoice::Reject => return Ok(()), // close without a cert
    };
    let tls = acceptor.accept()?;
    let mut session = Session::tls(shared.cfg.clone(), tls);
    crate::rt::common::serve_blocking_prefed(&mut stream, &mut session, &initial)
}

/// Accept loop for the plain-HTTP listener (redirects + ACME HTTP-01). One
/// thread per connection — this listener carries little traffic.
pub(crate) fn run_http_redirect(listener: TcpListener, ctx: HttpCtx) {
    let ctx = Arc::new(ctx);
    for incoming in listener.incoming() {
        match incoming {
            Ok(mut stream) => {
                let ctx = Arc::clone(&ctx);
                thread::spawn(move || {
                    stream.set_nodelay(true).ok();
                    if let Err(e) = redirect::serve(&mut stream, &ctx)
                        && cfg!(debug_assertions) {
                            eprintln!("httpsd: http connection ended: {e}");
                        }
                });
            }
            Err(e) => eprintln!("httpsd: http accept error: {e}"),
        }
    }
}
