use crate::addr::TargetAddr;
use crate::config::*;
use crate::proxy::{Proxy, backoff_delay};
use crate::socks5::udp::{MAX_HEADER, encode_header, parse_header};
use crate::socks5::{CMD_UDP_ASSOCIATE, SocksError, fix_relay_addr};
use crate::stats::Stats;
use arc_swap::ArcSwapOption;
use dashmap::DashMap;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = s.set_recv_buffer_size(UDP_SOCK_BUF);
    let _ = s.set_send_buffer_size(UDP_SOCK_BUF);
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    UdpSocket::from_std(s.into())
}

struct Assoc {
    relay: Arc<UdpSocket>,
    header: [u8; MAX_HEADER],
    header_len: usize,
}

#[derive(Default)]
struct Pending {
    q: VecDeque<Vec<u8>>,
    bytes: usize,
}

struct Session {
    client: SocketAddr,
    assoc: ArcSwapOption<Assoc>,
    pending: Mutex<Pending>,
    born: Instant,
    last_active: AtomicU64,
}

impl Session {
    fn touch(&self) {
        self.last_active.store(self.born.elapsed().as_millis() as u64, Relaxed);
    }

    fn idle_ms(&self) -> u64 {
        (self.born.elapsed().as_millis() as u64).saturating_sub(self.last_active.load(Relaxed))
    }
}

pub struct UdpForward {
    pub listener: Arc<UdpSocket>,
    pub target: TargetAddr,
    pub proxy: Arc<Proxy>,
    pub stats: Arc<Stats>,
    pub max_sessions: usize,
}

type Sessions = Arc<DashMap<SocketAddr, Arc<Session>>>;

impl UdpForward {
    pub async fn run(self, cancel: CancellationToken, tracker: TaskTracker) {
        let sessions: Sessions = Arc::new(DashMap::new());
        let target = Arc::new(self.target.clone());
        // Room in front of the payload for the SOCKS UDP header.
        let mut buf = vec![0u8; MAX_HEADER + UDP_MAX_DATAGRAM];
        loop {
            let (n, client) = tokio::select! {
                _ = cancel.cancelled() => return,
                r = self.listener.recv_from(&mut buf[MAX_HEADER..]) => match r {
                    Ok(v) => v,
                    Err(e) => {
                        // e.g. ICMP-induced errors on some platforms; never spin.
                        tracing::debug!("udp listener recv error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                        continue;
                    }
                }
            };
            self.stats.udp_pkts_up.fetch_add(1, Relaxed);
            self.stats.udp_bytes_up.fetch_add(n as u64, Relaxed);

            let existing = sessions.get(&client).map(|e| e.value().clone());
            let session = match existing {
                Some(s) => s,
                None => {
                    if sessions.len() >= self.max_sessions {
                        self.stats.udp_dropped.fetch_add(1, Relaxed);
                        continue;
                    }
                    let s = Arc::new(Session {
                        client,
                        assoc: ArcSwapOption::empty(),
                        pending: Mutex::new(Pending::default()),
                        born: Instant::now(),
                        last_active: AtomicU64::new(0),
                    });
                    sessions.insert(client, s.clone());
                    self.stats.udp_sessions_active.fetch_add(1, Relaxed);
                    self.stats.udp_sessions_total.fetch_add(1, Relaxed);
                    let task = SessionTask {
                        session: s.clone(),
                        sessions: sessions.clone(),
                        listener: self.listener.clone(),
                        target: target.clone(),
                        proxy: self.proxy.clone(),
                        stats: self.stats.clone(),
                        cancel: cancel.clone(),
                    };
                    tracker.spawn(task.run());
                    s
                }
            };
            session.touch();

            if let Some(a) = session.assoc.load().as_ref() {
                self.send_up(a, &mut buf, n).await;
                continue;
            }
            // Not connected yet: queue. Re-check under the lock to avoid racing the flush.
            let mut p = session.pending.lock().unwrap();
            if let Some(a) = session.assoc.load_full() {
                drop(p);
                self.send_up(&a, &mut buf, n).await;
                continue;
            }
            p.q.push_back(buf[MAX_HEADER..MAX_HEADER + n].to_vec());
            p.bytes += n;
            while p.q.len() > UDP_PENDING_MAX_PKTS || p.bytes > UDP_PENDING_MAX_BYTES {
                if let Some(old) = p.q.pop_front() {
                    p.bytes -= old.len();
                    self.stats.udp_dropped.fetch_add(1, Relaxed);
                } else {
                    break;
                }
            }
        }
    }

    /// Prepend the header in the spare room before the payload and send without copying.
    async fn send_up(&self, a: &Assoc, buf: &mut [u8], n: usize) {
        let start = MAX_HEADER - a.header_len;
        buf[start..MAX_HEADER].copy_from_slice(&a.header[..a.header_len]);
        if a.relay.send(&buf[start..MAX_HEADER + n]).await.is_err() {
            self.stats.udp_dropped.fetch_add(1, Relaxed);
        }
    }
}

struct SessionTask {
    session: Arc<Session>,
    sessions: Sessions,
    listener: Arc<UdpSocket>,
    target: Arc<TargetAddr>,
    proxy: Arc<Proxy>,
    stats: Arc<Stats>,
    cancel: CancellationToken,
}

struct Connected {
    control: TcpStream,
    relay: Arc<UdpSocket>,
    assoc: Arc<Assoc>,
}

enum Ended {
    Lost(String),
    Idle,
    Cancelled,
}

impl SessionTask {
    async fn run(self) {
        let mut attempts: u32 = 0;
        let mut was_connected = false;
        loop {
            if self.session.idle_ms() > UDP_IDLE_TIMEOUT.as_millis() as u64 {
                break;
            }
            let conn = tokio::select! {
                _ = self.cancel.cancelled() => break,
                r = self.connect() => r,
            };
            match conn {
                Ok(c) => {
                    attempts = 0;
                    if was_connected {
                        self.stats.udp_reconnects.fetch_add(1, Relaxed);
                        tracing::info!("udp {}: association restored", self.session.client);
                    } else {
                        tracing::debug!("udp {}: association established", self.session.client);
                    }
                    was_connected = true;
                    let assoc = c.assoc.clone();
                    self.flush_pending(c.assoc.clone()).await;
                    let why = self.serve(c).await;
                    self.session.assoc.store(None);
                    drop(assoc);
                    match why {
                        Ended::Idle | Ended::Cancelled => break,
                        Ended::Lost(m) => {
                            tracing::info!("udp {}: association lost: {m}", self.session.client);
                            // Brief pause so a flapping proxy cannot cause a hot loop.
                            tokio::time::sleep(backoff_delay(0)).await;
                        }
                    }
                }
                Err(e) => {
                    if matches!(e, SocksError::Reply(0x07)) {
                        tracing::error!("proxy does not support UDP ASSOCIATE");
                    } else {
                        tracing::debug!("udp {}: associate failed: {e}", self.session.client);
                    }
                    attempts = attempts.saturating_add(1);
                    tokio::select! {
                        _ = self.cancel.cancelled() => break,
                        _ = tokio::time::sleep(backoff_delay(attempts)) => {}
                    }
                }
            }
        }
        self.session.assoc.store(None);
        let me = &self.session;
        self.sessions.remove_if(&me.client, |_, v| Arc::ptr_eq(v, me));
        self.stats.udp_sessions_active.fetch_sub(1, Relaxed);
        tracing::debug!("udp {}: session closed", me.client);
    }

    async fn connect(&self) -> Result<Connected, SocksError> {
        self.proxy.health.wait_ready().await;

        // Many proxies reject domain names in UDP headers: resolve locally.
        let dst = match &*self.target {
            TargetAddr::Ip(a) => *a,
            TargetAddr::Domain(d, p) => tokio::net::lookup_host((d.as_str(), *p))
                .await?
                .next()
                .ok_or(SocksError::Protocol("target did not resolve"))?,
        };
        let (header, header_len) =
            encode_header(&TargetAddr::Ip(dst)).map_err(SocksError::Protocol)?;

        let unspec = TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        let (control, proxy_addr, bnd) = self.proxy.handshake(CMD_UDP_ASSOCIATE, &unspec).await?;

        let relay_addr = match fix_relay_addr(&bnd, proxy_addr.ip()) {
            Ok(a) => a,
            Err((d, p)) => tokio::net::lookup_host((d.as_str(), p))
                .await?
                .next()
                .ok_or(SocksError::Protocol("relay host did not resolve"))?,
        };
        if relay_addr.port() == 0 {
            return Err(SocksError::Protocol("relay port is zero"));
        }
        let local: SocketAddr = if relay_addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let relay = bind_udp(local)?;
        relay.connect(relay_addr).await?;
        let relay = Arc::new(relay);
        let assoc = Arc::new(Assoc { relay: relay.clone(), header, header_len });
        Ok(Connected { control, relay, assoc })
    }

    async fn flush_pending(&self, assoc: Arc<Assoc>) {
        let queued: Vec<Vec<u8>> = {
            let mut p = self.session.pending.lock().unwrap();
            self.session.assoc.store(Some(assoc.clone()));
            p.bytes = 0;
            p.q.drain(..).collect()
        };
        let mut out = Vec::with_capacity(MAX_HEADER + UDP_MAX_DATAGRAM);
        for pkt in queued {
            out.clear();
            out.extend_from_slice(&assoc.header[..assoc.header_len]);
            out.extend_from_slice(&pkt);
            if assoc.relay.send(&out).await.is_err() {
                self.stats.udp_dropped.fetch_add(1, Relaxed);
            }
        }
    }

    async fn serve(&self, mut c: Connected) -> Ended {
        let mut rbuf = vec![0u8; MAX_HEADER + UDP_MAX_DATAGRAM];
        let mut cbuf = [0u8; 64];
        let mut tick = tokio::time::interval(UDP_IDLE_TICK);
        let idle_ms = UDP_IDLE_TIMEOUT.as_millis() as u64;
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => return Ended::Cancelled,
                r = c.control.read(&mut cbuf) => match r {
                    Ok(0) => return Ended::Lost("control connection closed".into()),
                    Ok(_) => {}
                    Err(e) => return Ended::Lost(format!("control connection: {e}")),
                },
                r = c.relay.recv(&mut rbuf) => match r {
                    Ok(n) => self.deliver(&rbuf[..n]).await,
                    Err(e) => return Ended::Lost(format!("relay socket: {e}")),
                },
                _ = tick.tick() => {
                    if self.session.idle_ms() > idle_ms {
                        return Ended::Idle;
                    }
                }
            }
        }
    }

    async fn deliver(&self, pkt: &[u8]) {
        let Some((_src, off)) = parse_header(pkt) else {
            self.stats.udp_dropped.fetch_add(1, Relaxed);
            return;
        };
        let payload = &pkt[off..];
        self.session.touch();
        match self.listener.send_to(payload, self.session.client).await {
            Ok(_) => {
                self.stats.udp_pkts_down.fetch_add(1, Relaxed);
                self.stats.udp_bytes_down.fetch_add(payload.len() as u64, Relaxed);
            }
            Err(_) => {
                self.stats.udp_dropped.fetch_add(1, Relaxed);
            }
        }
    }
}
