use crate::addr::TargetAddr;
use clap::Parser;
use percent_encoding::percent_decode_str;

#[derive(Parser, Debug)]
#[command(name = "socks-gateway", version, about = "Forward local TCP+UDP ports through a SOCKS5 proxy")]
pub struct Args {
    /// SOCKS5 proxy: [socks5://][user:pass@]host:port
    #[arg(short = 'p', long = "proxy", value_parser = parse_proxy)]
    pub proxy: ProxyConfig,

    /// Forward LPORT:HOST:RPORT (TCP and UDP). Repeatable.
    #[arg(short = 'l', long = "listen", required = true, value_parser = parse_forward)]
    pub listen: Vec<Forward>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Creds {
    pub user: Vec<u8>,
    pub pass: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub creds: Option<Creds>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    pub local_port: u16,
    pub target: TargetAddr,
}

fn parse_port(s: &str) -> Result<u16, String> {
    match s.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("invalid port '{s}' (must be 1-65535)")),
        Ok(p) => Ok(p),
    }
}

pub fn parse_forward(s: &str) -> Result<Forward, String> {
    let (lport, rest) = s
        .split_once(':')
        .ok_or("expected LPORT:HOST:RPORT")?;
    let local_port = parse_port(lport)?;
    let (host, rport) = rest.rsplit_once(':').ok_or("expected LPORT:HOST:RPORT")?;
    let rport = parse_port(rport)?;
    let host = if let Some(inner) = host.strip_prefix('[') {
        inner.strip_suffix(']').ok_or("unclosed '[' in host")?
    } else {
        if host.contains(':') {
            return Err("IPv6 hosts must be written in brackets".into());
        }
        host
    };
    if host.is_empty() {
        return Err("empty host".into());
    }
    if host.len() > 255 {
        return Err("host too long".into());
    }
    Ok(Forward { local_port, target: TargetAddr::from_host_port(host, rport) })
}

pub fn parse_proxy(s: &str) -> Result<ProxyConfig, String> {
    let s = s.strip_prefix("socks5://").unwrap_or(s);
    let (auth, hostport) = match s.rsplit_once('@') {
        Some((a, h)) => (Some(a), h),
        None => (None, s),
    };
    let creds = match auth {
        None => None,
        Some(a) => {
            let (u, p) = a.split_once(':').ok_or("credentials must be user:pass")?;
            let user = percent_decode_str(u).collect::<Vec<u8>>();
            let pass = percent_decode_str(p).collect::<Vec<u8>>();
            if user.is_empty() || user.len() > 255 || pass.is_empty() || pass.len() > 255 {
                return Err("username and password must each be 1-255 bytes".into());
            }
            Some(Creds { user, pass })
        }
    };
    let hostport = hostport.trim_end_matches('/');
    let (host, port) = hostport.rsplit_once(':').ok_or("proxy must include a port")?;
    let host = match host.strip_prefix('[') {
        Some(inner) => inner.strip_suffix(']').ok_or("unclosed '[' in proxy host")?,
        None => host,
    };
    if host.is_empty() {
        return Err("empty proxy host".into());
    }
    Ok(ProxyConfig { host: host.to_string(), port: parse_port(port)?, creds })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_ok() {
        let f = parse_forward("8080:example.com:80").unwrap();
        assert_eq!(f.local_port, 8080);
        assert_eq!(f.target, TargetAddr::Domain("example.com".into(), 80));
        let f = parse_forward("53:1.1.1.1:53").unwrap();
        assert!(matches!(f.target, TargetAddr::Ip(_)));
        let f = parse_forward("22:[2001:db8::5]:22").unwrap();
        assert!(matches!(f.target, TargetAddr::Ip(a) if a.is_ipv6()));
    }

    #[test]
    fn forward_bad() {
        for s in ["", "80", "80:host", "0:h:80", "80:h:65536", "80:[::1:80", "80:::1:80", "80::80"] {
            assert!(parse_forward(s).is_err(), "{s}");
        }
    }

    #[test]
    fn proxy_ok() {
        let p = parse_proxy("socks5://bob:p%40ss@10.0.0.2:1080").unwrap();
        assert_eq!(p.host, "10.0.0.2");
        assert_eq!(p.port, 1080);
        assert_eq!(p.creds.unwrap().pass, b"p@ss");
        let p = parse_proxy("host:1").unwrap();
        assert!(p.creds.is_none());
        let p = parse_proxy("[::1]:1080").unwrap();
        assert_eq!(p.host, "::1");
    }

    #[test]
    fn proxy_bad() {
        for s in ["host", "u@host:1", "u:@host:1", "host:0", ":1080"] {
            assert!(parse_proxy(s).is_err(), "{s}");
        }
        let long = "a".repeat(256);
        assert!(parse_proxy(&format!("{long}:x@h:1")).is_err());
    }
}
