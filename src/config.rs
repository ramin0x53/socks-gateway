use std::time::Duration;

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const TCP_CONNECT_BUDGET: Duration = Duration::from_secs(15);
pub const BACKOFF_MIN: Duration = Duration::from_millis(100);
pub const BACKOFF_MAX: Duration = Duration::from_secs(5);

#[cfg(not(test))]
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
#[cfg(test)]
pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

pub const UDP_IDLE_TICK: Duration = Duration::from_secs(1);
pub const UDP_PENDING_MAX_PKTS: usize = 64;
pub const UDP_PENDING_MAX_BYTES: usize = 256 * 1024;

pub const MAX_TCP_CONNS_PER_PORT: usize = 10_000;
pub const MAX_UDP_SESSIONS_PER_PORT: usize = 10_000;

pub const TCP_COPY_BUF: usize = 64 * 1024;
pub const UDP_SOCK_BUF: usize = 4 * 1024 * 1024;
pub const UDP_MAX_DATAGRAM: usize = 65_535;
pub const PROXY_DNS_CACHE_TTL: Duration = Duration::from_secs(30);
pub const STATS_INTERVAL: Duration = Duration::from_secs(60);
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

pub const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
