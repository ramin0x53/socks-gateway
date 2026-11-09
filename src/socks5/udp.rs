use crate::addr::TargetAddr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MAX_HEADER: usize = 22;

/// Build the SOCKS5 UDP request header for `target` (RSV RSV FRAG ATYP ADDR PORT).
pub fn encode_header(target: &TargetAddr) -> Result<([u8; MAX_HEADER], usize), &'static str> {
    let mut v = Vec::with_capacity(MAX_HEADER);
    v.extend_from_slice(&[0, 0, 0]);
    target.write_socks(&mut v)?;
    if v.len() > MAX_HEADER {
        return Err("header too long for UDP");
    }
    let mut out = [0u8; MAX_HEADER];
    out[..v.len()].copy_from_slice(&v);
    Ok((out, v.len()))
}

/// Parse a SOCKS5 UDP header. Returns the source address and payload offset.
pub fn parse_header(b: &[u8]) -> Option<(SocketAddr, usize)> {
    if b.len() < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
        return None;
    }
    match b[3] {
        0x01 => {
            if b.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            Some((SocketAddr::new(IpAddr::V4(ip), u16::from_be_bytes([b[8], b[9]])), 10))
        }
        0x04 => {
            if b.len() < 22 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[4..20]);
            Some((SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), u16::from_be_bytes([b[20], b[21]])), 22))
        }
        0x03 => {
            let n = *b.get(4)? as usize;
            let off = 5 + n + 2;
            if b.len() < off {
                return None;
            }
            // Domain-sourced replies: report unspecified address, caller only needs the offset.
            let port = u16::from_be_bytes([b[off - 2], b[off - 1]]);
            Some((SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port), off))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_v4() {
        let t = TargetAddr::Ip("1.2.3.4:53".parse().unwrap());
        let (h, n) = encode_header(&t).unwrap();
        assert_eq!(n, 10);
        let mut pkt = h[..n].to_vec();
        pkt.extend_from_slice(b"hi");
        let (a, off) = parse_header(&pkt).unwrap();
        assert_eq!(a, "1.2.3.4:53".parse().unwrap());
        assert_eq!(&pkt[off..], b"hi");
    }

    #[test]
    fn roundtrip_v6_max() {
        let t = TargetAddr::Ip("[2001:db8::1]:53".parse().unwrap());
        let (h, n) = encode_header(&t).unwrap();
        assert_eq!(n, MAX_HEADER);
        assert_eq!(parse_header(&h[..n]).unwrap().1, 22);
    }

    #[test]
    fn domain_header() {
        let t = TargetAddr::Domain("ab".into(), 9);
        let (h, n) = encode_header(&t).unwrap();
        assert_eq!(n, 9);
        assert_eq!(parse_header(&h[..n]).unwrap().1, 9);
        let long = TargetAddr::Domain("a".repeat(30), 9);
        assert!(encode_header(&long).is_err());
    }

    #[test]
    fn rejects_bad() {
        assert!(parse_header(&[0, 0, 1, 1, 1, 2, 3, 4, 0, 1]).is_none()); // FRAG != 0
        assert!(parse_header(&[0, 0, 0, 1, 1, 2]).is_none()); // short
        assert!(parse_header(&[0, 0, 0, 9, 0, 0]).is_none()); // atyp
        assert!(parse_header(&[]).is_none());
    }
}
