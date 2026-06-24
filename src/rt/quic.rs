//! The QUIC/UDP server runtime that carries HTTP/3.
//!
//! A single UDP socket is multiplexed across clients, keyed by peer address
//! (QUIC connection migration is out of scope, so the address is stable for a
//! connection's lifetime). Each datagram is fed to its
//! [`QuicConnection`](purecrypto::quic::QuicConnection); the per-connection
//! [`H3Conn`] then services any complete requests, and the connection's
//! outbound datagrams are written back. Loss-recovery timers are driven from
//! the socket read timeout.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use purecrypto::quic::QuicConnection;

use crate::error::{Error, Result};
use crate::h3::H3Conn;
use crate::session::SessionConfig;
use crate::tls::TlsAcceptor;

/// QUIC datagrams must fit a conservative MTU; 1350 is the usual safe ceiling,
/// we read into a slightly larger buffer.
const RECV_BUF: usize = 2048;
/// Fallback poll interval when no connection has a pending timer.
const IDLE_POLL: Duration = Duration::from_millis(200);

struct Conn {
    quic: QuicConnection,
    h3: H3Conn,
    /// When the next loss-recovery timer should fire.
    deadline: Option<Instant>,
}

/// Bind a UDP socket and serve HTTP/3 until a fatal socket error.
pub(crate) fn run(addrs: Vec<SocketAddr>, cfg: SessionConfig, acceptor: TlsAcceptor) -> Result<()> {
    let socket = bind_first(&addrs)?;
    let start = Instant::now();
    let mut conns: HashMap<SocketAddr, Conn> = HashMap::new();
    let mut buf = [0u8; RECV_BUF];

    loop {
        // Wake at the soonest pending timer, or after the idle interval.
        let now = Instant::now();
        let wait = conns
            .values()
            .filter_map(|c| c.deadline)
            .map(|d| d.saturating_duration_since(now))
            .min()
            .unwrap_or(IDLE_POLL)
            .max(Duration::from_millis(1));
        socket.set_read_timeout(Some(wait)).ok();

        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let data = buf[..n].to_vec();
                if let Err(e) = on_datagram(&socket, &mut conns, peer, &data, &cfg, &acceptor) {
                    if cfg!(debug_assertions) {
                        eprintln!("httpsd: h3 connection error from {peer}: {e}");
                    }
                    conns.remove(&peer);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(Error::Io(e)),
        }

        fire_timers(&socket, &mut conns, &cfg, start);
        conns.retain(|_, c| !c.quic.is_closed());
    }
}

fn bind_first(addrs: &[SocketAddr]) -> Result<UdpSocket> {
    let mut last = None;
    for addr in addrs {
        match UdpSocket::bind(addr) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last
        .map(Error::Io)
        .unwrap_or_else(|| Error::Config("no listen address".into())))
}

fn on_datagram(
    socket: &UdpSocket,
    conns: &mut HashMap<SocketAddr, Conn>,
    peer: SocketAddr,
    data: &[u8],
    cfg: &SessionConfig,
    acceptor: &TlsAcceptor,
) -> Result<()> {
    if let std::collections::hash_map::Entry::Vacant(slot) = conns.entry(peer) {
        let qcfg = acceptor.quic_config()?;
        let quic = QuicConnection::server(qcfg).map_err(qerr)?;
        slot.insert(Conn {
            quic,
            h3: H3Conn::new(cfg.limits, cfg.server_name.clone()),
            deadline: None,
        });
    }
    let conn = conns.get_mut(&peer).unwrap();
    conn.quic.set_now_secs(unix_secs());
    conn.quic.feed_datagram_from(peer, data).map_err(qerr)?;
    service(socket, peer, conn, cfg)
}

/// Fire any elapsed loss-recovery timers and service those connections.
fn fire_timers(
    socket: &UdpSocket,
    conns: &mut HashMap<SocketAddr, Conn>,
    cfg: &SessionConfig,
    start: Instant,
) {
    let now = Instant::now();
    let due: Vec<SocketAddr> = conns
        .iter()
        .filter(|(_, c)| c.deadline.is_some_and(|d| d <= now))
        .map(|(addr, _)| *addr)
        .collect();
    for peer in due {
        if let Some(conn) = conns.get_mut(&peer) {
            conn.quic.on_timeout(now.saturating_duration_since(start));
            let _ = service(socket, peer, conn, cfg);
        }
    }
}

/// Run the HTTP/3 engine, flush outbound datagrams, and refresh the timer.
fn service(socket: &UdpSocket, peer: SocketAddr, conn: &mut Conn, cfg: &SessionConfig) -> Result<()> {
    conn.h3.drive(&mut conn.quic, cfg)?;
    loop {
        let dg = conn.quic.pop_datagram();
        if dg.is_empty() {
            break;
        }
        socket.send_to(&dg, peer)?;
    }
    // `next_timeout` is relative to now; store it as an absolute instant.
    conn.deadline = conn.quic.next_timeout().map(|d| Instant::now() + d);
    Ok(())
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn qerr<E: std::fmt::Debug>(e: E) -> Error {
    Error::Tls(format!("quic: {e:?}"))
}
