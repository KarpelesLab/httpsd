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
use crate::session::{Session, SessionConfig};

#[cfg(feature = "tls")]
use crate::tls::TlsAcceptor;

/// Shared, immutable per-server context handed to each worker.
struct Shared {
    cfg: SessionConfig,
    #[cfg(feature = "tls")]
    tls: Option<TlsAcceptor>,
}

/// Run a blocking accept loop, dispatching connections to `workers` threads.
///
/// Blocks the calling thread until the listener errors fatally (it never
/// returns under normal operation).
pub(crate) fn run(
    listener: TcpListener,
    cfg: SessionConfig,
    #[cfg(feature = "tls")] tls: Option<TlsAcceptor>,
    workers: usize,
) -> Result<()> {
    let shared = Arc::new(Shared {
        cfg,
        #[cfg(feature = "tls")]
        tls,
    });

    let workers = workers.max(1);
    let (tx, rx): (Sender<TcpStream>, Receiver<TcpStream>) = std::sync::mpsc::channel();
    let rx = Arc::new(Mutex::new(rx));

    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let rx = Arc::clone(&rx);
        let shared = Arc::clone(&shared);
        handles.push(thread::spawn(move || worker_loop(rx, shared)));
    }

    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                // If all workers have gone, stop accepting.
                if tx.send(stream).is_err() {
                    break;
                }
            }
            Err(e) => {
                // Transient accept errors shouldn't kill the server.
                eprintln!("httpsd: accept error: {e}");
            }
        }
    }
    Ok(())
}

fn worker_loop(rx: Arc<Mutex<Receiver<TcpStream>>>, shared: Arc<Shared>) {
    loop {
        // Hold the lock only long enough to dequeue one connection.
        let stream = {
            let guard = match rx.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            guard.recv()
        };
        let Ok(stream) = stream else {
            return; // channel closed
        };
        if let Err(e) = handle(stream, &shared) {
            // Connection-level errors are expected (resets, timeouts); log at
            // a low volume rather than crashing the worker.
            if cfg!(debug_assertions) {
                eprintln!("httpsd: connection ended: {e}");
            }
        }
    }
}

fn handle(stream: TcpStream, shared: &Shared) -> Result<()> {
    stream.set_nodelay(true).ok();

    #[cfg(feature = "tls")]
    if let Some(acceptor) = &shared.tls {
        let tls = acceptor.accept()?;
        let mut session = Session::tls(shared.cfg.clone(), tls);
        let mut stream = stream;
        return serve_blocking(&mut stream, &mut session);
    }

    let mut session = Session::plain(shared.cfg.clone());
    let mut stream = stream;
    serve_blocking(&mut stream, &mut session)
}
