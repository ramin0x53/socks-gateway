# socks-gateway

A small, fast Rust CLI that opens local ports and forwards **TCP and UDP** traffic on each one through a single **SOCKS5 proxy** to a fixed target host and port.

## Build

```
cargo build --release
```

The binary is `target/release/socks-gateway`.

## Usage

```
socks-gateway -p [socks5://][user:pass@]host:port -l LPORT:HOST:RPORT [-l ...]
```

| Flag | Required | Description |
|---|---|---|
| `-p`, `--proxy` | yes | The SOCKS5 proxy. The `socks5://` prefix is optional. Credentials may be URL-encoded (`%40` for `@`) and must each be 1-255 bytes. |
| `-l`, `--listen` | yes, repeatable | `LPORT:HOST:RPORT`. Opens TCP and UDP on `0.0.0.0:LPORT` and forwards both to `HOST:RPORT`. `HOST` can be a domain, an IPv4 address or `[IPv6]`. |

Examples:

```
socks-gateway -p 127.0.0.1:1080 -l 8080:example.com:80

socks-gateway -p socks5://bob:s3cret@10.0.0.2:1080 \
  -l 5353:1.1.1.1:53 \
  -l 2222:[2001:db8::5]:22
```

All ports are bound before anything is served. If a port is invalid, used twice, or can't be bound, the app exits with an error.

Set `RUST_LOG` to change the log level (default `info`), for example `RUST_LOG=debug`.

## Behaviour

### TCP
- Each client connection gets its own SOCKS5 CONNECT. The target is sent as a domain name, so the proxy does the DNS lookup.
- Proxy failures (connect errors, timeouts, handshake errors) are retried for up to 15 seconds. Target errors such as "connection refused" close the client connection immediately.
- A connection that is already open cannot survive a proxy restart, because it is a single end-to-end TCP stream. New connections work as soon as the proxy is back.

### UDP
- Each client address gets its own SOCKS5 UDP ASSOCIATE session, so replies always reach the right client.
- Packets that arrive while a session is being set up are queued (up to 64 packets / 256 KB), so the first packet is not lost.
- If the association drops (control connection closed, relay socket error), the session reconnects automatically with backoff. The client does not need to do anything. Packets sent during the reconnect are queued or dropped, as normal for UDP.
- A session with no traffic for 60 seconds is closed.
- Lost datagrams are **not** retransmitted. The app reduces loss with large socket buffers, the pending queue and fast reconnects.
- Target hostnames are resolved locally for UDP, because many proxies reject domain names in UDP packets.
- If the proxy reports an unspecified relay address (`0.0.0.0`/`::`), or a private one while the proxy itself is public, the proxy's own IP is used instead.

### Proxy health
All connections share one exponential backoff with jitter (100 ms up to 5 s), so a proxy that is down isn't hammered. Authentication failures are logged as errors at most once every 30 seconds.

### Limits and shutdown
- Up to 10,000 TCP connections and 10,000 UDP sessions per port, lowered automatically if the open-file limit is low. The limit is raised to its maximum at startup.
- Ctrl-C or SIGTERM stops accepting new connections and waits up to 5 seconds for open ones.
- A stats line is logged every 60 seconds when anything has changed.

## Requirements and limitations
- **UDP needs a proxy that supports UDP ASSOCIATE** (for example Dante, 3proxy, gost, Xray/V2Ray, sing-box, shadowsocks-local). `ssh -D` and microsocks do not. With those, UDP fails with a logged error while TCP keeps working.
- Fragmented SOCKS5 UDP packets (`FRAG` not 0) are dropped.
- Listening is on IPv4 (`0.0.0.0`) only.
- Only username/password or no authentication is supported.

## Tests

```
cargo test
cargo test --test e2e -- --test-threads=1
```

The unit tests cover argument parsing, SOCKS5 encoding and the UDP header. The end-to-end tests start a fake SOCKS5 proxy and cover TCP and UDP forwarding, authentication, a refused target, and recovery after the proxy is killed and restarted.
