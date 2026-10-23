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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use purecrypto::quic::QuicConnection;

use crate::error::{Error, Result};
use crate::h3::H3Conn;
use crate::proto::ConnInfo;
use crate::rt::shutdown::Shutdown;
use crate::session::SessionConfig;
use crate::tls::{ReloadableAcceptor, TlsAcceptor};

#[cfg(feature = "acme")]
use crate::acme::{AcmeManager, CertChoice};

/// Where the QUIC listener gets a certificate for each new connection.
pub(crate) enum CertSource {
    /// One static certificate for every connection (reloadable on SIGHUP).
    Static(ReloadableAcceptor),
    /// Per-SNI certificates from ACME, selected by peeking the QUIC Initial.
    #[cfg(feature = "acme")]
    Acme(AcmeManager),
}

/// What [`CertSource::acceptor_for`] decided for a new connection.
#[cfg_attr(not(feature = "acme"), allow(dead_code))]
enum Choice {
    /// Serve with this acceptor; the SNI, if the peek recovered it.
    Ready(Arc<TlsAcceptor>, Option<String>),
    /// The ClientHello isn't complete in the datagrams so far: keep them and
    /// retry when the client's next datagram arrives.
    NeedMore,
    /// Drop the datagrams (not a readable Initial, host not served, or no cert
    /// issued yet — the client retries or falls back to TCP).
    Drop,
}

impl CertSource {
    /// Choose the acceptor for a new connection from the client's first
    /// datagram(s), in arrival order. A ClientHello carrying a post-quantum
    /// key share (curl, current browsers) spans two datagrams, so the caller
    /// keeps them on [`Choice::NeedMore`] and calls again with the next one.
    ///
    /// The acceptor is an `Arc<TlsAcceptor>` so both arms unify: the static
    /// source hands out the reloadable cell's current acceptor by shared
    /// reference, while ACME yields a freshly owned one wrapped in an `Arc`.
    #[cfg_attr(not(feature = "acme"), allow(unused_variables))]
    fn acceptor_for(&self, peer: SocketAddr, datagrams: &[&[u8]]) -> Choice {
        // The QUIC ClientHello rides in the encrypted Initial; peek its SNI
        // without committing to a connection.
        let peek = purecrypto::quic::peek_initial_sni_datagrams(datagrams);
        match self {
            // One certificate for everyone: the SNI is only informational.
            CertSource::Static(reloadable) => Choice::Ready(
                reloadable.current(),
                peek.ok().flatten().and_then(|info| info.server_name),
            ),
            #[cfg(feature = "acme")]
            CertSource::Acme(mgr) => {
                let info = match peek {
                    Ok(Some(info)) => info,
                    Ok(None) => return Choice::NeedMore,
                    Err(_) => return Choice::Drop,
                };
                match mgr.choose_cached(info.server_name.as_deref(), peer.ip().is_loopback()) {
                    CertChoice::Serve(acceptor) => {
                        Choice::Ready(Arc::new(acceptor), info.server_name)
                    }
                    CertChoice::Reject => Choice::Drop,
                }
            }
        }
    }
}

/// The first datagrams of a client whose ClientHello is not complete yet
/// (held only while choosing its certificate).
struct PendingInitial {
    since: Instant,
    datagrams: Vec<Vec<u8>>,
}

/// Cap on clients whose first datagrams are held at once. Each holds at most
/// [`SNI_PROBE_MAX`] datagrams of at most [`RECV_BUF`] bytes, so the table is
/// bounded (~8 MiB) even under a flood of spoofed Initials.
const MAX_PENDING_INITIALS: usize = 1024;
/// How long held datagrams wait for the rest of their ClientHello. The rest
/// normally arrives right behind the first datagram.
const PENDING_INITIAL_TTL: Duration = Duration::from_secs(2);

/// QUIC datagrams must fit a conservative MTU; 1350 is the usual safe ceiling,
/// we read into a slightly larger buffer.
const RECV_BUF: usize = 2048;
/// Fallback poll interval when no connection has a pending timer.
const IDLE_POLL: Duration = Duration::from_millis(200);
/// Poll interval while some response body is streaming. A blocking UDP read
/// can't be interrupted by a producer, so the loop checks back this often and
/// services connections whose stream signalled new data.
const STREAM_POLL: Duration = Duration::from_millis(10);
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
    /// When this connection's `QuicConnection` was constructed. The purecrypto
    /// timer API works in durations measured from construction (both
    /// `next_timeout()` and `on_timeout()`), so we anchor deadlines to this.
    created_at: Instant,
    /// When the next loss-recovery timer should fire.
    deadline: Option<Instant>,
    /// Last time we received a datagram for this connection (for the idle sweep).
    last_seen: Instant,
    /// The client's first datagrams, kept while its SNI is unknown: a
    /// ClientHello with a post-quantum key share spans two datagrams.
    sni_probe: Option<Vec<Vec<u8>>>,
}

/// Datagrams kept for the SNI peek before giving up on it.
const SNI_PROBE_MAX: usize = 4;

/// The connection info attached to every HTTP/3 request.
fn h3_conn_info(
    peer: SocketAddr,
    local: Option<SocketAddr>,
    server_name: Option<String>,
) -> Arc<ConnInfo> {
    Arc::new(
        ConnInfo::new()
            .with_peer_addr(Some(peer))
            .with_local_addr(local)
            .with_secure(true)
            .with_tls_version(Some("TLSv1.3"))
            .with_alpn(Some(b"h3".to_vec()))
            .with_server_name(server_name),
    )
}

/// Bind a UDP socket and serve HTTP/3 until a fatal socket error.
pub(crate) fn run(
    addrs: Vec<SocketAddr>,
    cfg: SessionConfig,
    certs: CertSource,
    ready: Option<Sender<()>>,
    shutdown: Shutdown,
) -> Result<()> {
    let socket = bind_first(&addrs)?;
    // The UDP socket is bound; signal readiness before entering the event loop so
    // an external coordinator may drop privileges.
    if let Some(ready) = ready {
        let _ = ready.send(());
    }
    let mut conns: HashMap<SocketAddr, Conn> = HashMap::new();
    let mut pending: HashMap<SocketAddr, PendingInitial> = HashMap::new();
    let mut buf = [0u8; RECV_BUF];
    // Set by stream-body producers (through each H3Conn's waker).
    let stream_dirty = Arc::new(AtomicBool::new(false));

    loop {
        // Graceful shutdown: stop the loop and return. This is best-effort — a
        // full QUIC CONNECTION_CLOSE drain (notifying every peer) is a future
        // improvement; for now H3 clients fall back to TCP or retry. We do flush
        // any already-queued outbound datagrams once, without blocking, so
        // responses in flight get one last chance to leave.
        if shutdown.is_triggered() {
            for (peer, conn) in conns.iter_mut() {
                loop {
                    let dg = conn.quic.pop_datagram();
                    if dg.is_empty() {
                        break;
                    }
                    if socket.send_to(&dg, *peer).is_err() {
                        break;
                    }
                }
            }
            return Ok(());
        }

        // Wake at the soonest pending timer, or after the idle interval.
        let now = Instant::now();
        let mut wait = conns
            .values()
            .filter_map(|c| c.deadline)
            .map(|d| d.saturating_duration_since(now))
            .min()
            .unwrap_or(IDLE_POLL)
            .max(Duration::from_millis(1));
        if conns.values().any(|c| c.h3.is_streaming()) {
            wait = wait.min(STREAM_POLL);
        }
        socket.set_read_timeout(Some(wait)).ok();

        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let data = buf[..n].to_vec();
                if let Err(e) = on_datagram(
                    &socket,
                    &mut conns,
                    &mut pending,
                    peer,
                    &data,
                    &cfg,
                    &certs,
                    &stream_dirty,
                ) {
                    if cfg!(debug_assertions) {
                        eprintln!("httpsd: h3 connection error from {peer}: {e}");
                    }
                    conns.remove(&peer);
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
            Err(e) => return Err(Error::Io(e)),
        }

        fire_timers(&socket, &mut conns, &cfg);
        if stream_dirty.swap(false, Ordering::AcqRel) {
            for (peer, conn) in conns.iter_mut() {
                if conn.h3.is_streaming() {
                    let _ = service(&socket, *peer, conn, &cfg);
                }
            }
        }
        // Reap closed connections, plus any that have been idle past the
        // backstop timeout (covers half-open / stalled handshakes that an
        // attacker could otherwise pile up faster than they expire).
        let now = Instant::now();
        conns.retain(|_, c| {
            !c.quic.is_closed() && now.saturating_duration_since(c.last_seen) < CONN_IDLE_TIMEOUT
        });
        pending.retain(|_, p| now.saturating_duration_since(p.since) < PENDING_INITIAL_TTL);
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

#[allow(clippy::too_many_arguments)]
fn on_datagram(
    socket: &UdpSocket,
    conns: &mut HashMap<SocketAddr, Conn>,
    pending: &mut HashMap<SocketAddr, PendingInitial>,
    peer: SocketAddr,
    data: &[u8],
    cfg: &SessionConfig,
    certs: &CertSource,
    stream_dirty: &Arc<AtomicBool>,
) -> Result<()> {
    // The datagrams to feed the connection: just this one, or — for a new
    // connection whose ClientHello spanned several — all of them, in order.
    let mut feed = vec![data.to_vec()];
    if !conns.contains_key(&peer) {
        // New connection: pick the certificate from the Initial's SNI,
        // together with any earlier datagrams of an incomplete ClientHello.
        let mut held = pending
            .remove(&peer)
            .map(|p| p.datagrams)
            .unwrap_or_default();
        held.push(data.to_vec());
        if held.len() > SNI_PROBE_MAX {
            held.remove(0);
        }
        let refs: Vec<&[u8]> = held.iter().map(Vec::as_slice).collect();
        let (acceptor, server_name) = match certs.acceptor_for(peer, &refs) {
            Choice::Ready(acceptor, server_name) => (acceptor, server_name),
            Choice::NeedMore => {
                hold_initial(pending, peer, held);
                return Ok(());
            }
            Choice::Drop => return Ok(()),
        };
        // Bound the connection table so spoofed source addresses can't exhaust
        // memory. At the cap, try to reclaim a closed/stuck connection; if none
        // can be reclaimed, drop this Initial without allocating any state.
        if conns.len() >= MAX_CONNS && !evict_one(conns) {
            return Ok(());
        }
        let qcfg = acceptor.quic_config()?;
        let quic = QuicConnection::server(qcfg).map_err(qerr)?;
        let mut h3 = H3Conn::new(cfg.limits, cfg.server_name.clone());
        // With a static cert the connection starts before the SNI is known;
        // keep peeking at the next datagrams for it.
        let sni_probe = server_name.is_none().then(|| held.clone());
        h3.set_conn_info(h3_conn_info(peer, socket.local_addr().ok(), server_name));
        {
            let dirty = Arc::clone(stream_dirty);
            h3.set_waker(move || dirty.store(true, Ordering::Release));
        }
        conns.insert(
            peer,
            Conn {
                quic,
                h3,
                created_at: Instant::now(),
                deadline: None,
                last_seen: Instant::now(),
                sni_probe,
            },
        );
        feed = held;
    } else if let Some(conn) = conns.get_mut(&peer) {
        probe_sni(socket, peer, conn, data);
    }
    let conn = conns.get_mut(&peer).unwrap();
    conn.last_seen = Instant::now();
    conn.quic.set_now_secs(unix_secs());
    for dg in &feed {
        conn.quic.feed_datagram_from(peer, dg).map_err(qerr)?;
    }
    service(socket, peer, conn, cfg)
}

/// Keep a client's first datagrams until the rest of its ClientHello arrives.
/// At the cap, the oldest held client is dropped (it falls back to retrying).
fn hold_initial(
    pending: &mut HashMap<SocketAddr, PendingInitial>,
    peer: SocketAddr,
    datagrams: Vec<Vec<u8>>,
) {
    if pending.len() >= MAX_PENDING_INITIALS {
        let oldest = pending
            .iter()
            .min_by_key(|(_, p)| p.since)
            .map(|(peer, _)| *peer);
        if let Some(oldest) = oldest {
            pending.remove(&oldest);
        }
    }
    let since = Instant::now();
    pending.insert(peer, PendingInitial { since, datagrams });
}

/// Retry the SNI peek with this datagram added to the ones kept so far, until
/// it succeeds, the handshake completes, or enough datagrams were tried.
fn probe_sni(socket: &UdpSocket, peer: SocketAddr, conn: &mut Conn, data: &[u8]) {
    let Some(probe) = conn.sni_probe.as_mut() else {
        return;
    };
    if conn.quic.is_handshake_complete() || probe.len() >= SNI_PROBE_MAX {
        conn.sni_probe = None;
        return;
    }
    probe.push(data.to_vec());
    let refs: Vec<&[u8]> = probe.iter().map(Vec::as_slice).collect();
    if let Ok(Some(info)) = purecrypto::quic::peek_initial_sni_datagrams(&refs) {
        conn.sni_probe = None;
        if info.server_name.is_some() {
            conn.h3.set_conn_info(h3_conn_info(
                peer,
                socket.local_addr().ok(),
                info.server_name,
            ));
        }
    }
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
fn fire_timers(socket: &UdpSocket, conns: &mut HashMap<SocketAddr, Conn>, cfg: &SessionConfig) {
    let now = Instant::now();
    let due: Vec<SocketAddr> = conns
        .iter()
        .filter(|(_, c)| c.deadline.is_some_and(|d| d <= now))
        .map(|(addr, _)| *addr)
        .collect();
    for peer in due {
        if let Some(conn) = conns.get_mut(&peer) {
            // `on_timeout()` expects the elapsed duration since this
            // connection's construction, so measure from its own `created_at`
            // (not the global server start).
            conn.quic
                .on_timeout(now.saturating_duration_since(conn.created_at));
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
    // `next_timeout()` returns a duration measured from the connection's
    // construction (not from now), so anchor the absolute deadline to
    // `created_at`. Anchoring to `Instant::now()` would push the deadline
    // further out as the connection ages, so PTO/idle timers would never fire.
    conn.deadline = conn.quic.next_timeout().map(|d| conn.created_at + d);
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

#[cfg(test)]
mod tests {
    use super::*;
    use purecrypto::quic::QuicConfig;

    /// A real client first flight from purecrypto's QUIC client. It offers a
    /// post-quantum key share, so its ClientHello spans two datagrams — like
    /// curl and current browsers.
    fn client_flight(server_name: &str) -> Vec<Vec<u8>> {
        let tls = purecrypto::tls::Config::builder()
            .rng(Arc::new(purecrypto::rng::OsRng))
            .tls_only()
            .server_name(server_name)
            .verify_certificates(false)
            .alpn(vec![b"h3".to_vec()])
            .build();
        let mut cfg = QuicConfig::default();
        cfg.tls = tls;
        let mut client = QuicConnection::client(cfg, server_name).unwrap();
        let mut flight = Vec::new();
        loop {
            let dg = client.pop_datagram();
            if dg.is_empty() {
                break;
            }
            flight.push(dg);
        }
        assert_eq!(flight.len(), 2, "expected a two-datagram ClientHello");
        flight
    }

    #[cfg(feature = "acme")]
    #[allow(clippy::field_reassign_with_default)] // AcmeConfig is non-exhaustive
    fn acme_source() -> CertSource {
        let dir = std::env::temp_dir().join(format!("httpsd-quic-test-{}", std::process::id()));
        let mut cfg = crate::acme::AcmeConfig::default();
        cfg.cert_dir = Some(dir);
        CertSource::Acme(AcmeManager::new(cfg).unwrap())
    }

    #[cfg(feature = "acme")]
    #[test]
    fn acme_waits_for_the_whole_client_hello() {
        let flight = client_flight("h3.example");
        let certs = acme_source();
        let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        assert!(matches!(
            certs.acceptor_for(peer, &[&flight[0]]),
            Choice::NeedMore
        ));
        match certs.acceptor_for(peer, &[&flight[0], &flight[1]]) {
            Choice::Ready(_, sni) => assert_eq!(sni.as_deref(), Some("h3.example")),
            _ => panic!("both datagrams together must select a certificate"),
        }
    }

    /// The whole path: the first datagram is held, the second completes the
    /// ClientHello, and the connection is created from both (the server
    /// answers with its handshake).
    #[cfg(feature = "acme")]
    #[test]
    fn two_datagram_initial_opens_a_connection() {
        let flight = client_flight("localhost");
        let certs = acme_source();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = client.local_addr().unwrap();
        let cfg = SessionConfig::new(Arc::new(|_: &crate::proto::Request| {
            crate::proto::Response::text("x")
        }));
        let dirty = Arc::new(AtomicBool::new(false));
        let mut conns = HashMap::new();
        let mut pending = HashMap::new();

        on_datagram(
            &server,
            &mut conns,
            &mut pending,
            peer,
            &flight[0],
            &cfg,
            &certs,
            &dirty,
        )
        .unwrap();
        assert!(
            conns.is_empty(),
            "no connection before the ClientHello is complete"
        );
        assert_eq!(pending.len(), 1);

        on_datagram(
            &server,
            &mut conns,
            &mut pending,
            peer,
            &flight[1],
            &cfg,
            &certs,
            &dirty,
        )
        .unwrap();
        assert!(conns.contains_key(&peer), "connection created");
        assert!(pending.is_empty());

        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; RECV_BUF];
        let (n, from) = client.recv_from(&mut buf).expect("server handshake reply");
        assert!(n > 0);
        assert_eq!(from, server.local_addr().unwrap());
    }

    #[test]
    fn held_initials_are_capped() {
        let mut pending = HashMap::new();
        for i in 0..(MAX_PENDING_INITIALS + 10) {
            let peer: SocketAddr = format!("10.0.{}.{}:443", i / 256, i % 256).parse().unwrap();
            hold_initial(&mut pending, peer, vec![vec![0u8; 8]]);
        }
        assert_eq!(pending.len(), MAX_PENDING_INITIALS);
    }
}
