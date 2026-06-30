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

#[cfg(feature = "acme")]
use crate::acme::{AcmeManager, CertChoice};

/// Where the QUIC listener gets a certificate for each new connection.
pub(crate) enum CertSource {
    /// One static certificate for every connection.
    Static(TlsAcceptor),
    /// Per-SNI certificates from ACME, selected by peeking the QUIC Initial.
    #[cfg(feature = "acme")]
    Acme(AcmeManager),
}

impl CertSource {
    /// Choose the acceptor for a new connection given its first datagram.
    /// Returns `None` to drop the datagram (SNI not yet available, host not
    /// permitted, or no cert issued yet — the client retries / falls back).
    #[cfg_attr(not(feature = "acme"), allow(unused_variables))]
    fn acceptor_for(&self, peer: SocketAddr, first_datagram: &[u8]) -> Option<TlsAcceptor> {
        match self {
            CertSource::Static(acceptor) => Some(acceptor.clone()),
            #[cfg(feature = "acme")]
            CertSource::Acme(mgr) => {
                // The QUIC ClientHello rides in the encrypted Initial; peek its
                // SNI without committing to a connection.
                let info = match purecrypto::quic::peek_initial_sni(first_datagram) {
                    Ok(Some(info)) => info,
                    // Need the full Initial, or not a ClientHello — wait for retry.
                    Ok(None) | Err(_) => return None,
                };
                match mgr.choose_cached(info.server_name.as_deref(), peer.ip().is_loopback()) {
                    CertChoice::Serve(acceptor) => Some(acceptor),
                    CertChoice::Reject => None,
                }
            }
        }
    }
}

/// QUIC datagrams must fit a conservative MTU; 1350 is the usual safe ceiling,
/// we read into a slightly larger buffer.
const RECV_BUF: usize = 2048;
/// Fallback poll interval when no connection has a pending timer.
const IDLE_POLL: Duration = Duration::from_millis(200);
/// Hard cap on concurrently-tracked QUIC connections. UDP source addresses are
/// trivially spoofable, so an unbounded `conns` map is a memory-exhaustion
/// vector: an attacker can send one Initial each from a flood of forged
/// addresses. Address validation / anti-amplification (RFC 9000 §8.1, the 3×
/// send limit and Retry) is enforced inside the purecrypto QUIC library, so a
/// spoofed Initial cannot make us reflect traffic; here we only bound the
/// amount of per-connection state we are willing to hold. Past the cap, new
/// Initials are dropped without allocating state (after first trying to evict a
/// closed or stuck/half-open connection).
const MAX_CONNS: usize = 4096;
/// Backstop idle timeout for sweeping connections out of `conns`. The library
/// also closes idle connections via the negotiated `max_idle_timeout`
/// (30s here) — this independent sweep guarantees state is reclaimed even for
/// connections that never make progress (e.g. a handshake that stalls).
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

struct Conn {
    quic: QuicConnection,
    h3: H3Conn,
    /// When the next loss-recovery timer should fire.
    deadline: Option<Instant>,
    /// Last time we received a datagram for this connection (for the idle sweep).
    last_seen: Instant,
}

/// Bind a UDP socket and serve HTTP/3 until a fatal socket error.
pub(crate) fn run(addrs: Vec<SocketAddr>, cfg: SessionConfig, certs: CertSource) -> Result<()> {
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
                if let Err(e) = on_datagram(&socket, &mut conns, peer, &data, &cfg, &certs) {
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
        // Reap closed connections, plus any that have been idle past the
        // backstop timeout (covers half-open / stalled handshakes that an
        // attacker could otherwise pile up faster than they expire).
        let now = Instant::now();
        conns.retain(|_, c| {
            !c.quic.is_closed() && now.saturating_duration_since(c.last_seen) < CONN_IDLE_TIMEOUT
        });
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
    certs: &CertSource,
) -> Result<()> {
    if !conns.contains_key(&peer) {
        // New connection: pick the certificate from the Initial's SNI.
        let Some(acceptor) = certs.acceptor_for(peer, data) else {
            return Ok(()); // SNI unavailable / host not served — drop, client retries
        };
        // Bound the connection table so spoofed source addresses can't exhaust
        // memory. At the cap, try to reclaim a closed/stuck connection; if none
        // can be reclaimed, drop this Initial without allocating any state.
        if conns.len() >= MAX_CONNS && !evict_one(conns) {
            return Ok(());
        }
        let qcfg = acceptor.quic_config()?;
        let quic = QuicConnection::server(qcfg).map_err(qerr)?;
        conns.insert(
            peer,
            Conn {
                quic,
                h3: H3Conn::new(cfg.limits, cfg.server_name.clone()),
                deadline: None,
                last_seen: Instant::now(),
            },
        );
    }
    let conn = conns.get_mut(&peer).unwrap();
    conn.last_seen = Instant::now();
    conn.quic.set_now_secs(unix_secs());
    conn.quic.feed_datagram_from(peer, data).map_err(qerr)?;
    service(socket, peer, conn, cfg)
}

/// Reclaim one connection to make room at the cap. Prefers a connection that is
/// already closed, then the least-recently-active half-open (handshake not
/// complete) connection, and finally the overall least-recently-active one.
/// Returns whether a connection was removed.
fn evict_one(conns: &mut HashMap<SocketAddr, Conn>) -> bool {
    let closed = conns
        .iter()
        .find(|(_, c)| c.quic.is_closed())
        .map(|(peer, _)| *peer);
    if let Some(peer) = closed {
        conns.remove(&peer);
        return true;
    }
    let half_open = conns
        .iter()
        .filter(|(_, c)| !c.quic.is_handshake_complete())
        .min_by_key(|(_, c)| c.last_seen)
        .map(|(peer, _)| *peer);
    let victim = half_open.or_else(|| {
        conns
            .iter()
            .min_by_key(|(_, c)| c.last_seen)
            .map(|(peer, _)| *peer)
    });
    match victim {
        Some(peer) => {
            conns.remove(&peer);
            true
        }
        None => false,
    }
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
fn service(
    socket: &UdpSocket,
    peer: SocketAddr,
    conn: &mut Conn,
    cfg: &SessionConfig,
) -> Result<()> {
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
