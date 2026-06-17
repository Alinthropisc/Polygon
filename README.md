# Polygon

**Advanced network stress-testing & reconnaissance framework.**

Polygon is a high-performance, Go-native rewrite of MHDDoS — rebuilt from scratch with production-grade architecture, 57 attack methods, and zero compromises on throughput.

---

## Features

- **57 attack methods** — 26 L7 HTTP, 21 L4, 7 diagnostic tools
- **Raw socket support** — SYN floods, ICMP, and 7 AMP amplification protocols (Linux)
- **WAF/CDN fingerprinting** — Cloudflare, OVH, DDoS-Guard, Akamai, Fastly, Incapsula
- **TLS fingerprinting** — identify and evade detection signatures
- **Port scanner** with banner grabbing
- **AMP amplification** — MEM, NTP, DNS, RDP, CLDAP, CHAR, ARD payloads
- **Proxy support** — HTTP, SOCKS4, SOCKS5 with live health checking
- **Real-time stats** — live PPS (packets/sec) and BPS (bytes/sec)
- **Lock-free ring buffer** and token bucket rate limiter
- **Concurrent goroutine pools** with context-based lifecycle management
- **Cross-platform** — Linux (full, including raw sockets), macOS/Windows (L7 + UDP)

---

## Architecture

Polygon is built around seven composable design patterns that eliminate overhead and keep the hot path allocation-free:

| Pattern | Purpose |
|---|---|
| **Strategy + Registry** | Zero-cost method dispatch; no switch statements, O(1) lookup |
| **Factory** | Typed worker creation per method family |
| **Functional Options** | Engine configuration without breaking API contracts |
| **Decorator** | Rate-limiting wrapper applied transparently to any worker |
| **Observer** | Health checker with `OnDown`/`OnUp` callbacks for proxy rotation |
| **Builder** | Composable HTTP request construction |
| **Lock-free Ring Buffer** | Shared payload pool between goroutines without mutex contention |

---

## Supported Methods

### L4 — Network Layer

| Method | Description |
|---|---|
| `TCP` | Raw TCP flood |
| `UDP` | UDP datagram flood |
| `SYN` | SYN flood (raw socket, Linux only) |
| `ICMP` | ICMP echo flood (raw socket, Linux only) |
| `MEM` | Memcached AMP amplification |
| `NTP` | NTP monlist amplification |
| `DNS` | DNS amplification |
| `RDP` | RDP amplification |
| `CLDAP` | CLDAP amplification |
| `CHAR` | Chargen amplification |
| `ARD` | Apple Remote Desktop amplification |
| `VSE` | Valve Source Engine flood |
| `TS3` | TeamSpeak 3 flood |
| `FIVEM` | FiveM game server flood |
| `FIVEM-TOKEN` | FiveM token-based flood |
| `OVH-UDP` | OVH-bypass UDP flood |
| `MINECRAFT` | Minecraft server flood |
| `MCBOT` | Minecraft bot flood |
| `MCPE` | Minecraft Pocket Edition flood |
| `CPS` | Connections-per-second flood |
| `CONNECTION` | Persistent connection exhaustion |

### L7 — Application Layer

| Method | Description |
|---|---|
| `GET` | HTTP GET flood |
| `POST` | HTTP POST flood |
| `HEAD` | HTTP HEAD flood |
| `OVH` | OVH-bypass HTTP flood |
| `CFBUAM` | Cloudflare BUAM challenge bypass |
| `BYPASS` | Generic WAF bypass |
| `DYN` | Dynamic header generation |
| `SLOW` | Slowloris connection hold |
| `NULL` | Null-byte payload |
| `COOKIE` | Cookie-rotating flood |
| `EVEN` | Even-distribution flood |
| `XMLRPC` | WordPress XMLRPC amplification |
| `STRESS` | High-concurrency stress flood |
| `KILLER` | Connection killer |
| `TOR` | Tor exit-node flood |
| `DGB` | DDoS-Guard bypass |
| `AVB` | Anti-DDoS bypass |
| `GSB` | Google Shield bypass |
| `BOT` | Bot emulation flood |
| `APACHE` | Apache Range header exploit |
| `RHEX` | Random hex path flood |
| `STOMP` | STOMP protocol flood |
| `CFOFF` | Cloudflare under-attack mode off |
| `CFON` | Cloudflare under-attack mode on |
| `BOMB` | HTTP fragmentation bomb |

### Tools — Diagnostics & Reconnaissance

| Method | Description |
|---|---|
| `INFO` | Target information gathering |
| `CFIP` | Cloudflare real-IP discovery |
| `DNS` | DNS record enumeration |
| `PING` | ICMP ping with statistics |
| `CHECK` | Target availability check |
| `DSTAT` | Live network interface statistics |
| `TSSRV` | TeamSpeak SRV record lookup |

---

## Installation

### Build from source

```bash
git clone https://github.com/your-org/polygon.git
cd polygon
go build -trimpath -ldflags="-s -w" -o bin/polygon ./cmd/polygon
```

### Go install

```bash
go install github.com/your-org/polygon/cmd/polygon@latest
```

### Docker

```bash
docker build -t polygon .
```

---

## Usage

```
polygon <threads> <duration> <method> <target> [proxy_file] [options]
```

### Examples

**HTTP GET flood — 100 threads, 60 seconds:**
```bash
polygon 100 60 GET https://example.com socks5.txt
```

**SYN flood — raw socket, Linux only:**
```bash
sudo polygon 200 120 SYN 192.0.2.1:80
```

**NTP amplification:**
```bash
sudo polygon 50 60 NTP 192.0.2.1:123
```

**Slowloris — 500 connections:**
```bash
polygon 500 300 SLOW https://example.com
```

**Cloudflare bypass with SOCKS5 proxies:**
```bash
polygon 150 90 BYPASS https://example.com proxies/socks5.txt
```

**Target reconnaissance:**
```bash
polygon 1 1 INFO https://example.com
```

---

## Docker Usage

Polygon requires elevated capabilities for raw socket methods (SYN, ICMP, AMP amplification). L7 and UDP methods work without them.

**With raw socket support (Linux host required):**
```bash
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN \
  polygon 100 60 SYN 192.0.2.1:80
```

**L7 only (no elevated caps required):**
```bash
docker run --rm polygon 100 60 GET https://example.com
```

**With proxy list mounted:**
```bash
docker run --rm -v $(pwd)/proxies:/proxies \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  polygon 200 60 BYPASS https://example.com /proxies/socks5.txt
```

---

## Platform Support

| Feature | Linux | macOS | Windows |
|---|:---:|:---:|:---:|
| L7 HTTP methods | Yes | Yes | Yes |
| UDP methods | Yes | Yes | Yes |
| SYN flood (raw socket) | Yes | No | No |
| ICMP flood (raw socket) | Yes | No | No |
| AMP amplification | Yes | No | No |

---

## Legal Disclaimer

**Polygon is provided for authorized security research, penetration testing, and network resilience testing only.**

Use of this tool against systems you do not own or have explicit written permission to test is illegal in most jurisdictions. The authors assume no liability for any misuse or damage caused by this software. Always obtain proper authorization before conducting any network stress tests.

**You are solely responsible for how you use this tool.**
