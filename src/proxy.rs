use crate::addr::TargetAddr;
use crate::cli::{Creds, ProxyConfig};
use crate::config::*;
use crate::socks5::{self, SocksError};
use crate::stats::Stats;
use socket2::{SockRef, TcpKeepalive};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

pub struct Health {
    failures: AtomicU32,
    /// Milliseconds since `epoch` before which no attempt should start.
    not_before_ms: AtomicU64,
    epoch: Instant,
}

impl Health {
    fn new() -> Self {
        Self { failures: AtomicU32::new(0), not_before_ms: AtomicU64::new(0), epoch: Instant::now() }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub async fn wait_ready(&self) {
        let nb = self.not_before_ms.load(Relaxed);
        let now = self.now_ms();
        if nb > now {
            tokio::time::sleep(Duration::from_millis(nb - now)).await;
        }
    }

    pub fn success(&self) {
        self.failures.store(0, Relaxed);
        self.not_before_ms.store(0, Relaxed);
    }

    pub fn failure(&self) {
        let n = self.failures.fetch_add(1, Relaxed).min(16);
        let d = backoff_delay(n);
        self.not_before_ms.store(self.now_ms() + d.as_millis() as u64, Relaxed);
    }
}

/// Exponential backoff with full jitter, bounded by BACKOFF_MIN..=BACKOFF_MAX.
pub fn backoff_delay(n: u32) -> Duration {
    let cap = BACKOFF_MIN
        .saturating_mul(1u32 << n.min(16))
        .min(BACKOFF_MAX);
    let ms = cap.as_millis() as u64;
    let jittered = fastrand::u64(ms / 2..=ms);
    Duration::from_millis(jittered.max(BACKOFF_MIN.as_millis() as u64 / 2))
}

pub struct Proxy {
    host: String,
    port: u16,
    pub creds: Option<Creds>,
    dns: Mutex<Option<(Instant, Vec<SocketAddr>)>>,
    pub health: Health,
    pub stats: Arc<Stats>,
    last_config_log: Mutex<Option<Instant>>,
}

impl Proxy {
    pub fn new(cfg: ProxyConfig, stats: Arc<Stats>) -> Arc<Self> {
        Arc::new(Self {
            host: cfg.host,
            port: cfg.port,
            creds: cfg.creds,
            dns: Mutex::new(None),
            health: Health::new(),
            stats,
            last_config_log: Mutex::new(None),
        })
    }

    pub fn describe(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub async fn resolve(&self) -> std::io::Result<Vec<SocketAddr>> {
        if let Some((t, v)) = &*self.dns.lock().unwrap()
            && t.elapsed() < PROXY_DNS_CACHE_TTL
        {
            return Ok(v.clone());
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((self.host.as_str(), self.port)).await?.collect();
        if addrs.is_empty() {
            return Err(std::io::Error::other("proxy host resolved to no addresses"));
        }
        *self.dns.lock().unwrap() = Some((Instant::now(), addrs.clone()));
        Ok(addrs)
    }

    fn invalidate_dns(&self) {
        *self.dns.lock().unwrap() = None;
    }

    /// Connect to the proxy, trying every resolved address. Returns the stream and the address used.
    pub async fn connect_tcp(&self) -> Result<(TcpStream, SocketAddr), SocksError> {
        let addrs = self.resolve().await?;
        let mut last = None;
        for a in addrs {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(a)).await {
                Ok(Ok(s)) => {
                    let _ = s.set_nodelay(true);
                    let _ = SockRef::from(&s).set_tcp_keepalive(&keepalive());
                    return Ok((s, a));
                }
                Ok(Err(e)) => last = Some(SocksError::Io(e)),
                Err(_) => last = Some(SocksError::Timeout),
            }
        }
        self.invalidate_dns();
        Err(last.unwrap_or(SocksError::Timeout))
    }

    /// Connect, negotiate and issue a command, all under one timeout.
    pub async fn handshake(
        &self,
        cmd: u8,
        target: &TargetAddr,
    ) -> Result<(TcpStream, SocketAddr, TargetAddr), SocksError> {
        let fut = async {
            let (mut s, addr) = self.connect_tcp().await?;
            socks5::negotiate(&mut s, self.creds.as_ref()).await?;
            let bnd = socks5::request(&mut s, cmd, target).await?;
            Ok::<_, SocksError>((s, addr, bnd))
        };
        let r = match tokio::time::timeout(HANDSHAKE_TIMEOUT, fut).await {
            Ok(r) => r,
            Err(_) => Err(SocksError::Timeout),
        };
        self.record(&r);
        r
    }

    fn record<T>(&self, r: &Result<T, SocksError>) {
        match r {
            Ok(_) => self.health.success(),
            Err(e) if e.is_proxy_failure() => {
                self.stats.proxy_failures.fetch_add(1, Relaxed);
                self.health.failure();
                tracing::warn!("proxy {}: {e}", self.describe());
            }
            Err(e) if e.is_config_failure() => {
                self.stats.proxy_failures.fetch_add(1, Relaxed);
                self.health.failure();
                let mut l = self.last_config_log.lock().unwrap();
                if l.is_none_or(|t| t.elapsed() > Duration::from_secs(30)) {
                    *l = Some(Instant::now());
                    tracing::error!("proxy {}: {e}", self.describe());
                }
            }
            // Target-level errors: the proxy itself responded properly.
            Err(_) => self.health.success(),
        }
    }
}

pub fn keepalive() -> TcpKeepalive {
    let k = TcpKeepalive::new().with_time(KEEPALIVE_IDLE);
    #[cfg(not(any(target_os = "openbsd", target_os = "redox", target_os = "solaris", target_os = "nto", target_os = "espidf", target_os = "vita", target_os = "haiku")))]
    let k = k.with_interval(KEEPALIVE_INTERVAL);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_bounds() {
        for n in 0..40 {
            for _ in 0..50 {
                let d = backoff_delay(n);
                assert!(d <= BACKOFF_MAX);
                assert!(d >= BACKOFF_MIN / 2);
            }
        }
    }
}
