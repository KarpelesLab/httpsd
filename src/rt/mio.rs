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

use mio::event::Event;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token};

use crate::error::{Error, Result};
use crate::rt::common::READ_BUF;
use crate::session::{Session, SessionConfig};

#[cfg(feature = "tls")]
use crate::tls::TlsAcceptor;

const LISTENER: Token = Token(0);

struct Conn {
    stream: TcpStream,
    session: Session,
    out: Vec<u8>,
    out_pos: usize,
    read_closed: bool,
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

    loop {
        poll.poll(&mut events, None)?;
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
                Ok(n) => conn.session.received(&buf[..n])?,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::Io(e)),
            }
        }
        let out = conn.session.to_send()?;
        conn.enqueue(out);
    }

    // Either a writable event or freshly produced output: try to drain.
    if event.is_writable() || conn.pending_out() {
        conn.flush_out()?;
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
