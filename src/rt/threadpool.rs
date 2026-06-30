//! Blocking runtime backed by a fixed pool of worker threads.
//!
//! The accept loop runs on the calling thread and hands each accepted socket to
//! a bounded set of worker threads over a channel. With one worker the server
//! is effectively single-threaded; with N workers up to N connections are
//! served concurrently. There is no async runtime involved.

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::error::Result;
use crate::rt::TlsMode;
use crate::rt::common::{self, serve_blocking};
use crate::rt::redirect::{self, HttpCtx};
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
    // Bound the queue of accepted-but-unserved connections. Each queued stream
    // holds an open descriptor, so an unbounded queue lets a connection burst
    // exhaust the fd limit (which is exactly what melted the server once). The
    // cap is generous — a safety ceiling, not tight backpressure — so it stays
    // well clear of normal concurrency, including the ACME path where one worker
    // blocks on issuance while another answers the validation connection. When
    // the queue is full `send` blocks the accept loop; further connections wait
    // in the kernel backlog and are shed there if it too fills.
    let backlog = workers.saturating_mul(64).clamp(256, 4096);
    let (tx, rx): (SyncSender<TcpStream>, Receiver<TcpStream>) =
        std::sync::mpsc::sync_channel(backlog);
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
            Err(e) => {
                if common::note_accept_error("accept error", &e) {
                    thread::sleep(common::ACCEPT_BACKOFF);
                }
            }
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
        // Isolate each connection: a panic while serving one client must not
        // kill the worker thread, which would permanently shrink the pool and,
        // once every worker died, wedge the whole server.
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle(stream, &shared)));
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) if cfg!(debug_assertions) => {
                eprintln!("httpsd: connection ended: {e}");
            }
            Ok(Err(_)) => {}
            Err(_) => eprintln!("httpsd: worker recovered from a panic while serving a connection"),
        }
    }
}

fn handle(mut stream: TcpStream, shared: &Shared) -> Result<()> {
    stream.set_nodelay(true).ok();
    common::apply_timeouts(&stream);

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
fn handle_acme(
    mut stream: TcpStream,
    shared: &Shared,
    mgr: &crate::acme::AcmeManager,
) -> Result<()> {
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

/// Accept loop for the plain-HTTP listener (redirects + ACME HTTP-01). It spawns
/// a thread per connection — these are short-lived (read a request, reply, close)
/// — but caps how many run at once so a flood can't spawn unbounded threads.
pub(crate) fn run_http_redirect(listener: TcpListener, ctx: HttpCtx) {
    /// Maximum redirect connections served concurrently; excess is shed.
    const MAX_INFLIGHT: usize = 256;

    let ctx = Arc::new(ctx);
    let inflight = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        match incoming {
            Ok(mut stream) => {
                common::apply_timeouts(&stream);
                stream.set_nodelay(true).ok();
                // Shed load past the cap by closing the connection (drop).
                if inflight.fetch_add(1, Ordering::Relaxed) >= MAX_INFLIGHT {
                    inflight.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }
                let ctx = Arc::clone(&ctx);
                let inflight = Arc::clone(&inflight);
                thread::spawn(move || {
                    if let Err(e) = redirect::serve(&mut stream, &ctx)
                        && cfg!(debug_assertions)
                    {
                        eprintln!("httpsd: http connection ended: {e}");
                    }
                    inflight.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) => {
                if common::note_accept_error("http accept error", &e) {
                    thread::sleep(common::ACCEPT_BACKOFF);
                }
            }
        }
    }
}
