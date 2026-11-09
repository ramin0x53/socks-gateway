use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Fake SOCKS5 proxy running in its own runtime; dropping it kills everything.
struct FakeProxy {
    rt: Option<tokio::runtime::Runtime>,
}

impl FakeProxy {
    fn start(port: u16, auth: Option<(&'static str, &'static str)>) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let l = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
        l.set_nonblocking(true).unwrap();
        rt.spawn(async move {
            let l = TcpListener::from_std(l).unwrap();
            loop {
                let (s, _) = l.accept().await.unwrap();
                tokio::spawn(proxy_conn(s, auth));
            }
        });
        FakeProxy { rt: Some(rt) }
    }

    fn kill(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

impl Drop for FakeProxy {
    fn drop(&mut self) {
        self.kill();
    }
}

async fn read_addr(s: &mut TcpStream, atyp: u8) -> SocketAddr {
    match atyp {
        1 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await.unwrap();
            SocketAddr::from(([b[0], b[1], b[2], b[3]], u16::from_be_bytes([b[4], b[5]])))
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            let mut b = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut b).await.unwrap();
            let port = u16::from_be_bytes([b[b.len() - 2], b[b.len() - 1]]);
            let host = String::from_utf8(b[..l[0] as usize].to_vec()).unwrap();
            tokio::net::lookup_host((host.as_str(), port)).await.unwrap().next().unwrap()
        }
        _ => panic!("unsupported atyp"),
    }
}

async fn proxy_conn(mut s: TcpStream, auth: Option<(&'static str, &'static str)>) {
    let mut h = [0u8; 2];
    if s.read_exact(&mut h).await.is_err() {
        return;
    }
    let mut methods = vec![0u8; h[1] as usize];
    s.read_exact(&mut methods).await.unwrap();
    match auth {
        None => s.write_all(&[5, 0]).await.unwrap(),
        Some((u, p)) => {
            if !methods.contains(&2) {
                s.write_all(&[5, 0xff]).await.unwrap();
                return;
            }
            s.write_all(&[5, 2]).await.unwrap();
            let mut v = [0u8; 2];
            s.read_exact(&mut v).await.unwrap();
            let mut user = vec![0u8; v[1] as usize];
            s.read_exact(&mut user).await.unwrap();
            let mut pl = [0u8; 1];
            s.read_exact(&mut pl).await.unwrap();
            let mut pass = vec![0u8; pl[0] as usize];
            s.read_exact(&mut pass).await.unwrap();
            if user != u.as_bytes() || pass != p.as_bytes() {
                s.write_all(&[1, 1]).await.unwrap();
                return;
            }
            s.write_all(&[1, 0]).await.unwrap();
        }
    }
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await.unwrap();
    let dst = read_addr(&mut s, r[3]).await;
    match r[1] {
        1 => {
            let Ok(t) = TcpStream::connect(dst).await else {
                s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                return;
            };
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            let (mut a, mut b) = (s, t);
            let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
        }
        3 => {
            let u = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let port = u.local_addr().unwrap().port().to_be_bytes();
            s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]]).await.unwrap();
            let mut client: Option<SocketAddr> = None;
            let mut buf = vec![0u8; 70000];
            let mut cb = [0u8; 8];
            loop {
                tokio::select! {
                    r = s.read(&mut cb) => { if matches!(r, Ok(0) | Err(_)) { return; } }
                    r = u.recv_from(&mut buf) => {
                        let (n, from) = r.unwrap();
                        if client.is_none() || client == Some(from) {
                            client = Some(from);
                            assert_eq!(buf[3], 1, "expected IPv4 header");
                            let to = SocketAddr::from(([buf[4], buf[5], buf[6], buf[7]], u16::from_be_bytes([buf[8], buf[9]])));
                            u.send_to(&buf[10..n], to).await.unwrap();
                        } else if let Some(c) = client {
                            let mut out = vec![0, 0, 0, 1];
                            if let SocketAddr::V4(a) = from {
                                out.extend_from_slice(&a.ip().octets());
                                out.extend_from_slice(&a.port().to_be_bytes());
                            }
                            out.extend_from_slice(&buf[..n]);
                            u.send_to(&out, c).await.unwrap();
                        }
                    }
                }
            }
        }
        _ => {}
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap().local_addr().unwrap().port()
}

struct Gateway(Child);

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_gateway(proxy: &str, forwards: &[(u16, String)]) -> Gateway {
    let mut c = Command::new(env!("CARGO_BIN_EXE_socks-gateway"));
    c.arg("-p").arg(proxy);
    for (lp, t) in forwards {
        c.arg("-l").arg(format!("{lp}:{t}"));
    }
    c.stdout(Stdio::null()).stderr(Stdio::null());
    Gateway(c.spawn().unwrap())
}

async fn wait_tcp(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("gateway did not start");
}

async fn tcp_echo() -> u16 {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

async fn udp_echo() -> u16 {
    let u = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = u.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut b = vec![0u8; 70000];
        loop {
            let (n, f) = u.recv_from(&mut b).await.unwrap();
            let _ = u.send_to(&b[..n], f).await;
        }
    });
    port
}

async fn tcp_roundtrip(port: u16, data: &[u8]) {
    let mut c = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
    let (mut r, mut w) = c.split();
    let d = data.to_vec();
    let wr = async {
        w.write_all(&d).await.unwrap();
        w.shutdown().await.unwrap();
    };
    let rd = async {
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        out
    };
    let (_, out) = tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(wr, rd) }).await.unwrap();
    assert_eq!(out.len(), data.len());
    assert!(out == data);
}

async fn udp_roundtrip(port: u16, payload: &[u8], wait: Duration) -> bool {
    let c = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    c.connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
    let mut b = vec![0u8; 70000];
    let deadline = tokio::time::Instant::now() + wait;
    while tokio::time::Instant::now() < deadline {
        c.send(payload).await.unwrap();
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(300), c.recv(&mut b)).await {
            return &b[..n] == payload;
        }
    }
    false
}

#[tokio::test]
async fn tcp_and_udp_through_proxy() {
    let pp = free_port();
    let _proxy = FakeProxy::start(pp, None);
    let (te, ue) = (tcp_echo().await, udp_echo().await);
    let (lt, lu) = (free_port(), free_port());
    // Same local port serves both protocols; use distinct forwards per echo port.
    let _g = start_gateway(&format!("127.0.0.1:{pp}"), &[(lt, format!("127.0.0.1:{te}")), (lu, format!("localhost:{ue}"))]);
    wait_tcp(lt).await;

    let big: Vec<u8> = (0..5_000_000u32).map(|i| (i % 251) as u8).collect();
    tcp_roundtrip(lt, &big).await;
    // 50 concurrent connections
    let mut hs = Vec::new();
    for i in 0..50u8 {
        hs.push(tokio::spawn(async move { tcp_roundtrip(lt, &[i; 1000]).await }));
    }
    for h in hs {
        h.await.unwrap();
    }

    assert!(udp_roundtrip(lu, b"hello udp", Duration::from_secs(5)).await);
    assert!(udp_roundtrip(lu, &vec![7u8; 8000], Duration::from_secs(5)).await);
}

#[tokio::test]
async fn udp_many_clients_get_own_replies() {
    let pp = free_port();
    let _proxy = FakeProxy::start(pp, None);
    let ue = udp_echo().await;
    let lu = free_port();
    let te = tcp_echo().await;
    let _g = start_gateway(&format!("127.0.0.1:{pp}"), &[(lu, format!("127.0.0.1:{ue}"))]);
    let _ = te;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut hs = Vec::new();
    for i in 0..100u32 {
        hs.push(tokio::spawn(async move {
            udp_roundtrip(lu, format!("client-{i}").as_bytes(), Duration::from_secs(8)).await
        }));
    }
    for h in hs {
        assert!(h.await.unwrap());
    }
}

#[tokio::test]
async fn auth_works_and_wrong_auth_fails() {
    let pp = free_port();
    let _proxy = FakeProxy::start(pp, Some(("bob", "p@ss")));
    let te = tcp_echo().await;

    let good = free_port();
    let _g = start_gateway(&format!("socks5://bob:p%40ss@127.0.0.1:{pp}"), &[(good, format!("127.0.0.1:{te}"))]);
    wait_tcp(good).await;
    tcp_roundtrip(good, b"authed").await;

    let bad = free_port();
    let _g2 = start_gateway(&format!("socks5://bob:nope@127.0.0.1:{pp}"), &[(bad, format!("127.0.0.1:{te}"))]);
    wait_tcp(bad).await;
    let mut c = TcpStream::connect((Ipv4Addr::LOCALHOST, bad)).await.unwrap();
    let _ = c.write_all(b"x").await;
    let mut b = [0u8; 8];
    let r = tokio::time::timeout(Duration::from_secs(20), c.read(&mut b)).await.unwrap();
    assert!(matches!(r, Ok(0) | Err(_)), "connection should be closed on auth failure");
}

#[tokio::test]
async fn target_refused_closes_client() {
    let pp = free_port();
    let _proxy = FakeProxy::start(pp, None);
    let dead = free_port();
    let l = free_port();
    let _g = start_gateway(&format!("127.0.0.1:{pp}"), &[(l, format!("127.0.0.1:{dead}"))]);
    wait_tcp(l).await;
    let mut c = TcpStream::connect((Ipv4Addr::LOCALHOST, l)).await.unwrap();
    let mut b = [0u8; 8];
    let r = tokio::time::timeout(Duration::from_secs(5), c.read(&mut b)).await.unwrap();
    assert!(matches!(r, Ok(0) | Err(_)));
}

#[tokio::test]
async fn recovers_after_proxy_restart() {
    let pp = free_port();
    let mut proxy = FakeProxy::start(pp, None);
    let (te, ue) = (tcp_echo().await, udp_echo().await);
    let (lt, lu) = (free_port(), free_port());
    let _g = start_gateway(&format!("127.0.0.1:{pp}"), &[(lt, format!("127.0.0.1:{te}")), (lu, format!("127.0.0.1:{ue}"))]);
    wait_tcp(lt).await;

    // Long-lived UDP client that keeps sending across the outage.
    let c = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    c.connect((Ipv4Addr::LOCALHOST, lu)).await.unwrap();
    let mut b = [0u8; 64];
    c.send(b"before").await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), c.recv(&mut b)).await.unwrap().unwrap();
    assert_eq!(&b[..n], b"before");

    proxy.kill();
    tokio::time::sleep(Duration::from_millis(500)).await;
    // While down, new TCP connections get closed without a reply.
    let mut d = TcpStream::connect((Ipv4Addr::LOCALHOST, lt)).await.unwrap();
    let _ = d.write_all(b"x").await;
    drop(d);

    let _proxy2 = restart(pp).await;

    // UDP: same client socket, no action required.
    let mut ok = false;
    for _ in 0..40 {
        c.send(b"after").await.unwrap();
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(300), c.recv(&mut b)).await
            && &b[..n] == b"after"
        {
            ok = true;
            break;
        }
    }
    assert!(ok, "udp session did not recover");
    // TCP: new connection works.
    tcp_roundtrip(lt, b"tcp after restart").await;
}

async fn restart(port: u16) -> FakeProxy {
    for _ in 0..50 {
        if std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return FakeProxy::start(port, None);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("port not released");
}
