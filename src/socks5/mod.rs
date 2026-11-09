pub mod udp;

use crate::addr::TargetAddr;
use crate::cli::Creds;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

#[derive(Debug, Error)]
pub enum SocksError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("timeout")]
    Timeout,
    #[error("protocol error: {0}")]
    Protocol(&'static str),
    #[error("no acceptable authentication method")]
    NoAcceptableMethod,
    #[error("authentication failed")]
    AuthFailed,
    #[error("proxy replied: {}", reply_text(*.0))]
    Reply(u8),
}

impl SocksError {
    /// True when the failure indicates the proxy itself is unhealthy
    /// (as opposed to the target or our configuration being at fault).
    pub fn is_proxy_failure(&self) -> bool {
        match self {
            SocksError::Io(_) | SocksError::Timeout | SocksError::Protocol(_) => true,
            SocksError::Reply(r) => *r == 0x01,
            SocksError::NoAcceptableMethod | SocksError::AuthFailed => false,
        }
    }

    /// Configuration problems that retrying will not fix by itself.
    pub fn is_config_failure(&self) -> bool {
        matches!(self, SocksError::NoAcceptableMethod | SocksError::AuthFailed)
    }

    /// Whether retrying the same request may help.
    pub fn is_retryable(&self) -> bool {
        match self {
            SocksError::Io(_) | SocksError::Timeout | SocksError::Protocol(_) => true,
            SocksError::Reply(r) => *r == 0x01,
            _ => false,
        }
    }
}

fn reply_text(r: u8) -> &'static str {
    match r {
        0x01 => "general failure",
        0x02 => "connection not allowed",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

pub async fn negotiate<S>(s: &mut S, creds: Option<&Creds>) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if creds.is_some() {
        s.write_all(&[5, 2, 0x00, 0x02]).await?;
    } else {
        s.write_all(&[5, 1, 0x00]).await?;
    }
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    if r[0] != 5 {
        return Err(SocksError::Protocol("bad version in method reply"));
    }
    match r[1] {
        0x00 => Ok(()),
        0x02 => {
            let c = creds.ok_or(SocksError::Protocol("proxy demanded auth we did not offer"))?;
            let mut m = Vec::with_capacity(3 + c.user.len() + c.pass.len());
            m.push(1);
            m.push(c.user.len() as u8);
            m.extend_from_slice(&c.user);
            m.push(c.pass.len() as u8);
            m.extend_from_slice(&c.pass);
            s.write_all(&m).await?;
            let mut a = [0u8; 2];
            s.read_exact(&mut a).await?;
            if a[1] != 0 {
                return Err(SocksError::AuthFailed);
            }
            Ok(())
        }
        0xFF => Err(SocksError::NoAcceptableMethod),
        _ => Err(SocksError::Protocol("unexpected auth method")),
    }
}

pub async fn request<S>(s: &mut S, cmd: u8, addr: &TargetAddr) -> Result<TargetAddr, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut m = Vec::with_capacity(22);
    m.extend_from_slice(&[5, cmd, 0]);
    addr.write_socks(&mut m).map_err(SocksError::Protocol)?;
    s.write_all(&m).await?;

    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    if h[0] != 5 {
        return Err(SocksError::Protocol("bad version in reply"));
    }
    if h[1] != 0 {
        // Drain nothing further; the connection is unusable anyway.
        return Err(SocksError::Reply(h[1]));
    }
    read_bound(s, h[3]).await
}

async fn read_bound<S: AsyncRead + Unpin>(s: &mut S, atyp: u8) -> Result<TargetAddr, SocksError> {
    match atyp {
        0x01 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), u16::from_be_bytes([b[4], b[5]]))))
        }
        0x04 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await?;
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[..16]);
            Ok(TargetAddr::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(o)),
                u16::from_be_bytes([b[16], b[17]]),
            )))
        }
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize + 2];
            s.read_exact(&mut b).await?;
            let port = u16::from_be_bytes([b[b.len() - 2], b[b.len() - 1]]);
            b.truncate(l[0] as usize);
            let d = String::from_utf8(b).map_err(|_| SocksError::Protocol("bad domain in reply"))?;
            Ok(TargetAddr::Domain(d, port))
        }
        _ => Err(SocksError::Protocol("unknown address type in reply")),
    }
}

/// Decide which address to send UDP datagrams to, given the proxy's BND reply.
/// Returns `Err(domain, port)` if the reply holds a domain that needs resolving.
pub fn fix_relay_addr(bnd: &TargetAddr, proxy_ip: IpAddr) -> Result<SocketAddr, (String, u16)> {
    match bnd {
        TargetAddr::Domain(d, p) => Err((d.clone(), *p)),
        TargetAddr::Ip(a) => {
            let ip = a.ip();
            let use_proxy = ip.is_unspecified() || (is_private(ip) && !is_private(proxy_ip));
            if use_proxy {
                Ok(SocketAddr::new(proxy_ip, a.port()))
            } else {
                Ok(*a)
            }
        }
    }
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        IpAddr::V6(v) => {
            v.is_loopback()
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn relay_unspecified() {
        let b = TargetAddr::Ip("0.0.0.0:4000".parse().unwrap());
        assert_eq!(fix_relay_addr(&b, ip("8.8.8.8")).unwrap(), "8.8.8.8:4000".parse().unwrap());
    }

    #[test]
    fn relay_private_behind_nat() {
        let b = TargetAddr::Ip("10.0.0.5:4000".parse().unwrap());
        assert_eq!(fix_relay_addr(&b, ip("8.8.8.8")).unwrap(), "8.8.8.8:4000".parse().unwrap());
        // Both private: trust the reply.
        assert_eq!(fix_relay_addr(&b, ip("10.0.0.1")).unwrap(), "10.0.0.5:4000".parse().unwrap());
        // Loopback proxy and loopback reply.
        let b = TargetAddr::Ip("127.0.0.1:4000".parse().unwrap());
        assert_eq!(fix_relay_addr(&b, ip("127.0.0.1")).unwrap(), "127.0.0.1:4000".parse().unwrap());
    }

    #[test]
    fn relay_public_and_domain() {
        let b = TargetAddr::Ip("1.2.3.4:4000".parse().unwrap());
        assert_eq!(fix_relay_addr(&b, ip("8.8.8.8")).unwrap(), "1.2.3.4:4000".parse().unwrap());
        let d = TargetAddr::Domain("x.y".into(), 5);
        assert_eq!(fix_relay_addr(&d, ip("8.8.8.8")), Err(("x.y".into(), 5)));
    }

    #[tokio::test]
    async fn connect_flow() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let mut b = [0u8; 3];
            s.read_exact(&mut b).await.unwrap();
            assert_eq!(b, [5, 1, 0]);
            s.write_all(&[5, 0]).await.unwrap();
            let mut h = [0u8; 4];
            s.read_exact(&mut h).await.unwrap();
            assert_eq!(h, [5, 1, 0, 3]);
            s.write_all(&[5, 0, 0, 1, 1, 2, 3, 4, 0, 80]).await.unwrap();
        });
        negotiate(&mut c, None).await.unwrap();
        let bnd = request(&mut c, CMD_CONNECT, &TargetAddr::Domain("a".into(), 1)).await;
        // server did not read the rest of the request; only ensure parse works
        assert_eq!(bnd.unwrap(), TargetAddr::Ip("1.2.3.4:80".parse().unwrap()));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn reply_error() {
        let (mut c, mut s) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut b = [0u8; 64];
            let _ = s.read(&mut b).await;
            s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
        });
        let r = request(&mut c, CMD_CONNECT, &TargetAddr::Ip("1.1.1.1:1".parse().unwrap())).await;
        assert!(matches!(r, Err(SocksError::Reply(5))));
    }
}
