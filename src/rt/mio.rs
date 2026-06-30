//! Single-thread readiness event-loop driver, built on mio.
//!
//! One `mio::Poll` multiplexes the listener and every connection on a single
//! thread with non-blocking sockets. Each connection keeps a sans-I/O
//! [`Session`] plus a small outbound buffer for bytes that couldn't be written
//! immediately; the loop tracks `WRITABLE` interest only while that buffer is
//! non-empty. The protocol/TLS/compression logic is identical to the other
//! runtimes.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};

use crate::error::{Error, Result};
use crate::rt::common::{IO_TIMEOUT, MIN_PROGRESS, READ_BUF};
use crate::session::{Session, SessionConfig};

#[cfg(feature = "tls")]
use crate::tls::TlsAcceptor;

const LISTENER: Token = Token(0);

/// Ceiling on simultaneously tracked connections. The connection map would grow
/// unbounded otherwise, letting a flood exhaust memory and file descriptors.
/// Accepts past the cap are shed (accepted then dropped so the kernel backlog
/// keeps draining).
const MAX_CONNS: usize = 8192;

/// How often the idle sweep runs. The single-thread loop has no per-connection
/// timer, so instead of a full timer wheel we wake `poll` at this cadence and
/// evict connections that have gone idle (a coarse but cheap simplification; the
/// worst-case extra lifetime of an idle/trickling peer is one interval past its
/// deadline).
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

struct Conn {
    stream: TcpStream,
    session: Session,
    out: Vec<u8>,
    out_pos: usize,
    read_closed: bool,
    /// Instant of the last window in which the peer met the [`MIN_PROGRESS`]
    /// throughput floor. A connection whose `progress_since` falls more than
    /// [`IO_TIMEOUT`] behind now is idle or slow-trickling and is evicted.
    progress_since: Instant,
    /// Bytes received in the current window (reset once it reaches the floor).
    progress_bytes: usize,
}

impl Conn {
    /// Record `n` freshly read bytes, advancing the progress window when the
    /// throughput floor is met. Returns nothing; eviction is decided by the
    /// periodic sweep against [`Self::progress_since`].
    fn note_progress(&mut self, n: usize, now: Instant) {
        self.progress_bytes = self.progress_bytes.saturating_add(n);
        if self.progress_bytes >= MIN_PROGRESS {
            self.progress_since = now;
            self.progress_bytes = 0;
        }
    }

    /// Whether the connection has failed the minimum-throughput rule: no full
    /// `MIN_PROGRESS` window completed within [`IO_TIMEOUT`].
    fn is_idle(&self, now: Instant) -> bool {
        now.duration_since(self.progress_since) > IO_TIMEOUT
    }
}

impl Conn {
    fn pending_out(&self) -> bool {
        self.out_pos < self.out.len()
    }

    fn interest(&self) -> Interest {
        if self.pending_out() {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        }
    }

    /// Queue freshly produced response bytes.
    fn enqueue(&mut self, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        if self.pending_out() {
            self.out.extend_from_slice(&bytes);
        } else {
            self.out = bytes;
            self.out_pos = 0;
        }
    }

    /// Write as much of the outbound buffer as the socket will take.
    fn flush_out(&mut self) -> std::io::Result<()> {
        while self.pending_out() {
            match self.stream.write(&self.out[self.out_pos..]) {
                Ok(0) => break,
                Ok(n) => self.out_pos += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        if !self.pending_out() {
            self.out.clear();
            self.out_pos = 0;
        }
        Ok(())
    }

    /// Whether the connection is finished and can be dropped.
    fn is_done(&self) -> bool {
        !self.pending_out() && (self.session.wants_close() || self.read_closed)
    }
}

/// Bind and serve on a single-thread mio event loop until a fatal error.
pub(crate) fn run(
    addrs: Vec<SocketAddr>,
    cfg: SessionConfig,
    #[cfg(feature = "tls")] tls: Option<TlsAcceptor>,
) -> Result<()> {
    let mut listener = bind_first(&addrs)?;
    let mut poll = Poll::new()?;
    poll.registry()
        .register(&mut listener, LISTENER, Interest::READABLE)?;

    let mut events = Events::with_capacity(1024);
    let mut conns: HashMap<Token, Conn> = HashMap::new();
    let mut next_token = 1usize;
    let mut next_sweep = Instant::now() + SWEEP_INTERVAL;

    loop {
        // Wake at least once per sweep interval so idle peers are reaped even
        // when no socket is otherwise readable/writable.
        poll.poll(&mut events, Some(SWEEP_INTERVAL))?;
        for event in events.iter() {
            match event.token() {
                LISTENER => accept_ready(
                    &listener,
                    &poll,
                    &cfg,
                    #[cfg(feature = "tls")]
                    &tls,
                    &mut conns,
                    &mut next_token,
                ),
                token => handle_conn(token, event, &poll, &mut conns),
            }
        }

        let now = Instant::now();
        if now >= next_sweep {
            sweep_idle(&poll, &mut conns, now);
            next_sweep = now + SWEEP_INTERVAL;
        }
    }
}

/// Evict connections that have failed the minimum-throughput rule (idle or
/// slow-trickle), deregistering and dropping them to free the descriptor.
fn sweep_idle(poll: &Poll, conns: &mut HashMap<Token, Conn>, now: Instant) {
    let stale: Vec<Token> = conns
        .iter()
        .filter(|(_, c)| c.is_idle(now))
        .map(|(t, _)| *t)
        .collect();
    for token in stale {
        if let Some(mut conn) = conns.remove(&token) {
            let _ = poll.registry().deregister(&mut conn.stream);
        }
    }
}

fn bind_first(addrs: &[SocketAddr]) -> Result<TcpListener> {
    let mut last = None;
    for addr in addrs {
        match TcpListener::bind(*addr) {
            Ok(l) => return Ok(l),
            Err(e) => last = Some(e),
        }
    }
    Err(last
        .map(Error::Io)
        .unwrap_or_else(|| Error::Config("no listen address".into())))
}

fn accept_ready(
    listener: &TcpListener,
    poll: &Poll,
    cfg: &SessionConfig,
    #[cfg(feature = "tls")] tls: &Option<TlsAcceptor>,
    conns: &mut HashMap<Token, Conn>,
    next_token: &mut usize,
) {
    loop {
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                stream.set_nodelay(true).ok();
                // Shed past the cap: drop the freshly accepted socket but keep
                // draining the backlog so the listener does not stay hot.
                if conns.len() >= MAX_CONNS {
                    drop(stream);
                    continue;
                }
                let session = match build_session(
                    cfg,
                    #[cfg(feature = "tls")]
                    tls,
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("httpsd: session init failed: {e}");
                        continue;
                    }
                };
                let token = Token(*next_token);
                *next_token += 1;
                if poll
                    .registry()
                    .register(&mut stream, token, Interest::READABLE)
                    .is_err()
                {
                    continue;
                }
                conns.insert(
                    token,
                    Conn {
                        stream,
                        session,
                        out: Vec::new(),
                        out_pos: 0,
                        read_closed: false,
                        progress_since: Instant::now(),
                        progress_bytes: 0,
                    },
                );
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => {
                if crate::rt::common::note_accept_error("accept error", &e) {
                    std::thread::sleep(crate::rt::common::ACCEPT_BACKOFF);
                }
                break;
            }
        }
    }
}

fn handle_conn(token: Token, event: &Event, poll: &Poll, conns: &mut HashMap<Token, Conn>) {
    let Some(conn) = conns.get_mut(&token) else {
        return;
    };

    let result = drive(conn, event);

    let finished = result.is_err() || conn.is_done();
    if finished {
        if let Some(mut conn) = conns.remove(&token) {
            let _ = poll.registry().deregister(&mut conn.stream);
        }
        return;
    }

    // Update readiness interest to reflect any newly buffered output.
    let interest = conn.interest();
    let _ = poll
        .registry()
        .reregister(&mut conn.stream, token, interest);
}

/// Process one readiness event for a connection.
fn drive(conn: &mut Conn, event: &Event) -> Result<()> {
    if event.is_readable() && !conn.read_closed {
        let mut buf = [0u8; READ_BUF];
        loop {
            match conn.stream.read(&mut buf) {
                Ok(0) => {
                    conn.read_closed = true;
                    break;
                }
                Ok(n) => {
                    conn.note_progress(n, Instant::now());
                    conn.session.received(&buf[..n])?;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Io(e)),
            }
        }
        // Queue whatever the engine produced now (handshake records or the first
        // response chunk); `pump_writes` then streams any remaining body.
        let out = conn.session.to_send()?;
        conn.enqueue(out);
    }

    // Drain the outbound buffer and, as the socket accepts more, pull the next
    // body chunk — so a file body is streamed without buffering it whole and
    // without stalling when the socket back-pressures.
    pump_writes(conn)?;
    Ok(())
}

/// Flush the outbound buffer, pulling successive body chunks from the session as
/// the socket drains. Stops when the socket back-pressures (the buffer is left
/// non-empty, so `WRITABLE` interest is re-armed) or the session has no more
/// output. Memory stays bounded: at most one chunk is buffered at a time.
fn pump_writes(conn: &mut Conn) -> Result<()> {
    loop {
        conn.flush_out()?;
        if conn.pending_out() {
            break; // socket full; wait for the next WRITABLE event
        }
        if !conn.session.has_output() {
            break;
        }
        let out = conn.session.to_send()?;
        if out.is_empty() {
            break;
        }
        conn.enqueue(out);
    }
    Ok(())
}

fn build_session(
    cfg: &SessionConfig,
    #[cfg(feature = "tls")] tls: &Option<TlsAcceptor>,
) -> Result<Session> {
    #[cfg(feature = "tls")]
    if let Some(acceptor) = tls {
        return Ok(Session::tls(cfg.clone(), acceptor.accept()?));
    }
    Ok(Session::plain(cfg.clone()))
}
