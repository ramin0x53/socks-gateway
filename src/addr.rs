use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(a) => a.port(),
            TargetAddr::Domain(_, p) => *p,
        }
    }

    /// Append the SOCKS5 ATYP + ADDR + PORT encoding.
    pub fn write_socks(&self, out: &mut Vec<u8>) -> Result<(), &'static str> {
        match self {
            TargetAddr::Ip(SocketAddr::V4(a)) => {
                out.push(0x01);
                out.extend_from_slice(&a.ip().octets());
            }
            TargetAddr::Ip(SocketAddr::V6(a)) => {
                out.push(0x04);
                out.extend_from_slice(&a.ip().octets());
            }
            TargetAddr::Domain(d, _) => {
                if d.is_empty() || d.len() > 255 {
                    return Err("domain length must be 1..=255");
                }
                out.push(0x03);
                out.push(d.len() as u8);
                out.extend_from_slice(d.as_bytes());
            }
        }
        out.extend_from_slice(&self.port().to_be_bytes());
        Ok(())
    }

    /// Parse a host string (domain, IPv4, or IPv6 without brackets) plus port.
    pub fn from_host_port(host: &str, port: u16) -> Self {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port))
        } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
            TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip), port))
        } else {
            TargetAddr::Domain(host.to_string(), port)
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(a) => write!(f, "{a}"),
            TargetAddr::Domain(d, p) => write!(f, "{d}:{p}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_domain() {
        let mut v = Vec::new();
        TargetAddr::Domain("a.b".into(), 80).write_socks(&mut v).unwrap();
        assert_eq!(v, [3, 3, b'a', b'.', b'b', 0, 80]);
    }

    #[test]
    fn encode_v4_v6() {
        let mut v = Vec::new();
        TargetAddr::from_host_port("1.2.3.4", 53).write_socks(&mut v).unwrap();
        assert_eq!(v, [1, 1, 2, 3, 4, 0, 53]);
        let mut v = Vec::new();
        TargetAddr::from_host_port("::1", 53).write_socks(&mut v).unwrap();
        assert_eq!(v.len(), 1 + 16 + 2);
    }
}
