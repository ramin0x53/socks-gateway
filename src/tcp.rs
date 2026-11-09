use crate::addr::TargetAddr;
use crate::config::*;
use crate::proxy::{Proxy, keepalive};
use crate::socks5::{CMD_CONNECT, SocksError};
use crate::stats::Stats;
use socket2::SockRef;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;
use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub struct TcpForward {
    pub listener: TcpListener,
    pub target: TargetAddr,
    pub proxy: Arc<Proxy>,
    pub stats: Arc<Stats>,
    pub max_conns: usize,
}

impl TcpForward {
    pub async fn run(self, cancel: CancellationToken, tracker: TaskTracker) {
        let sem = Arc::new(Semaphore::new(self.max_conns));
        let target = Arc::new(self.target);
        loop {
            let (client, peer) = tokio::select! {
                _ = cancel.cancelled() => return,
                r = self.listener.accept() => match r {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("tcp accept error: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                }
            };
            let Ok(permit) = sem.clone().try_acquire_owned() else {
                self.stats.tcp_rejected.fetch_add(1, Relaxed);
                tracing::debug!("tcp {peer}: rejected, connection limit reached");
                continue;
            };
            let _ = client.set_nodelay(true);
            let _ = SockRef::from(&client).set_tcp_keepalive(&keepalive());
            let proxy = self.proxy.clone();
            let stats = self.stats.clone();
            let target = target.clone();
            let cancel = cancel.clone();
            tracker.spawn(async move {
                let _permit = permit;
                stats.tcp_active.fetch_add(1, Relaxed);
                stats.tcp_total.fetch_add(1, Relaxed);
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    _ = handle(client, peer, &target, &proxy, &stats) => {}
                }
                stats.tcp_active.fetch_sub(1, Relaxed);
            });
        }
    }
}

async fn connect_with_retry(proxy: &Proxy, target: &TargetAddr) -> Result<TcpStream, SocksError> {
    let attempt = async {
        loop {
            proxy.health.wait_ready().await;
            match proxy.handshake(CMD_CONNECT, target).await {
                Ok((s, _, _)) => return Ok(s),
                Err(e) if e.is_retryable() => continue,
                Err(e) => return Err(e),
            }
        }
    };
    match tokio::time::timeout(TCP_CONNECT_BUDGET, attempt).await {
        Ok(r) => r,
        Err(_) => Err(SocksError::Timeout),
    }
}

async fn handle(mut client: TcpStream, peer: std::net::SocketAddr, target: &TargetAddr, proxy: &Proxy, stats: &Stats) {
    let start = std::time::Instant::now();
    let mut upstream = match connect_with_retry(proxy, target).await {
        Ok(s) => s,
        Err(e) => {
            stats.tcp_failed.fetch_add(1, Relaxed);
            tracing::debug!("tcp {peer} -> {target}: connect failed: {e}");
            return;
        }
    };
    match copy_bidirectional_with_sizes(&mut client, &mut upstream, TCP_COPY_BUF, TCP_COPY_BUF).await {
        Ok((up, down)) => {
            stats.tcp_bytes_up.fetch_add(up, Relaxed);
            stats.tcp_bytes_down.fetch_add(down, Relaxed);
            tracing::debug!("tcp {peer} -> {target}: closed after {:?} (up {up}, down {down})", start.elapsed());
        }
        Err(e) => tracing::debug!("tcp {peer} -> {target}: {e}"),
    }
}
