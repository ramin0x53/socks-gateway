use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct Stats {
    pub tcp_active: AtomicU64,
    pub tcp_total: AtomicU64,
    pub tcp_failed: AtomicU64,
    pub tcp_rejected: AtomicU64,
    pub tcp_bytes_up: AtomicU64,
    pub tcp_bytes_down: AtomicU64,
    pub udp_sessions_active: AtomicU64,
    pub udp_sessions_total: AtomicU64,
    pub udp_pkts_up: AtomicU64,
    pub udp_pkts_down: AtomicU64,
    pub udp_bytes_up: AtomicU64,
    pub udp_bytes_down: AtomicU64,
    pub udp_dropped: AtomicU64,
    pub udp_reconnects: AtomicU64,
    pub proxy_failures: AtomicU64,
}

impl Stats {
    fn snapshot(&self) -> [u64; 15] {
        [
            self.tcp_active.load(Relaxed),
            self.tcp_total.load(Relaxed),
            self.tcp_failed.load(Relaxed),
            self.tcp_rejected.load(Relaxed),
            self.tcp_bytes_up.load(Relaxed),
            self.tcp_bytes_down.load(Relaxed),
            self.udp_sessions_active.load(Relaxed),
            self.udp_sessions_total.load(Relaxed),
            self.udp_pkts_up.load(Relaxed),
            self.udp_pkts_down.load(Relaxed),
            self.udp_bytes_up.load(Relaxed),
            self.udp_bytes_down.load(Relaxed),
            self.udp_dropped.load(Relaxed),
            self.udp_reconnects.load(Relaxed),
            self.proxy_failures.load(Relaxed),
        ]
    }
}

pub async fn report_loop(stats: std::sync::Arc<Stats>, every: Duration, cancel: CancellationToken) {
    let mut last = stats.snapshot();
    let mut tick = tokio::time::interval(every);
    tick.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tick.tick() => {}
        }
        let s = stats.snapshot();
        // Skip when only gauges could have changed and nothing moved.
        if s == last {
            continue;
        }
        tracing::info!(
            tcp_active = s[0], tcp_total = s[1], tcp_failed = s[2], tcp_rejected = s[3],
            tcp_up = s[4], tcp_down = s[5],
            udp_sessions = s[6], udp_sessions_total = s[7],
            udp_pkts_up = s[8], udp_pkts_down = s[9],
            udp_bytes_up = s[10], udp_bytes_down = s[11],
            udp_dropped = s[12], udp_reconnects = s[13], proxy_failures = s[14],
            "stats"
        );
        last = s;
    }
}
