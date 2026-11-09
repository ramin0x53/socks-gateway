mod addr;
mod cli;
mod config;
mod proxy;
mod socks5;
mod stats;
mod tcp;
mod udp;

use anyhow::{Context, Result};
use clap::Parser;
use config::*;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    s.listen(1024)?;
    TcpListener::from_std(s.into())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = cli::Args::parse();

    let mut seen = std::collections::HashSet::new();
    for f in &args.listen {
        if !seen.insert(f.local_port) {
            anyhow::bail!("local port {} specified more than once", f.local_port);
        }
    }

    // Each connection can use up to ~2 descriptors (TCP) or 2 (UDP control + relay).
    let nofile = rlimit::increase_nofile_limit(u64::MAX).unwrap_or(1024) as usize;
    let ports = args.listen.len().max(1);
    let budget = nofile.saturating_sub(64) / (2 * 2 * ports);
    let per_port = MAX_TCP_CONNS_PER_PORT.min(budget).max(16);
    if per_port < MAX_TCP_CONNS_PER_PORT {
        tracing::warn!("open file limit {nofile} is low; limiting to {per_port} connections per port");
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(args, per_port.min(MAX_UDP_SESSIONS_PER_PORT)))
}

async fn run(args: cli::Args, per_port: usize) -> Result<()> {
    let stats = Arc::new(stats::Stats::default());
    let proxy = proxy::Proxy::new(args.proxy, stats.clone());
    let cancel = CancellationToken::new();
    let tracker = TaskTracker::new();

    // Bind everything first so a failure exits before serving anything.
    let mut tcps = Vec::new();
    let mut udps = Vec::new();
    for f in args.listen {
        let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, f.local_port));
        let tl = bind_tcp(addr).with_context(|| format!("cannot bind TCP port {}", f.local_port))?;
        let ul = udp::bind_udp(addr).with_context(|| format!("cannot bind UDP port {}", f.local_port))?;
        tracing::info!("{addr} <-> {} via {} (tcp+udp)", f.target, proxy.describe());
        tcps.push(tcp::TcpForward {
            listener: tl,
            target: f.target.clone(),
            proxy: proxy.clone(),
            stats: stats.clone(),
            max_conns: per_port,
        });
        udps.push(udp::UdpForward {
            listener: Arc::new(ul),
            target: f.target,
            proxy: proxy.clone(),
            stats: stats.clone(),
            max_sessions: per_port,
        });
    }

    for t in tcps {
        tokio::spawn(t.run(cancel.clone(), tracker.clone()));
    }
    for u in udps {
        tokio::spawn(u.run(cancel.clone(), tracker.clone()));
    }
    tokio::spawn(stats::report_loop(stats.clone(), STATS_INTERVAL, cancel.clone()));

    shutdown_signal().await;
    tracing::info!("shutting down");
    cancel.cancel();
    tracker.close();
    if tokio::time::timeout(SHUTDOWN_GRACE, tracker.wait()).await.is_err() {
        tracing::warn!("some tasks did not finish within the grace period");
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
