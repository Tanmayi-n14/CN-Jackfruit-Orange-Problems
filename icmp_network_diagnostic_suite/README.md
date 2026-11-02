# 🌐 ICMP Diagnostic Suite — Raw Socket Core Module

> A combined **Ping + Traceroute** network diagnostic tool built from scratch using **raw ICMP sockets** — no calls to system `ping`/`traceroute` binaries. Pure socket-level implementation in Python and C.

This is **Person 1's core module** — the foundational layer that Person 2 (Ping) and Person 3 (Traceroute) build upon.

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                     ICMP DIAGNOSTIC SUITE                     │
├──────────────┬──────────────────┬────────────────────────────┤
│  Person 2    │   Person 1       │   Person 3                 │
│  PING MODULE │   CORE MODULE ◄──┤   TRACEROUTE MODULE        │
│              │                  │                            │
│  - RTT stats │   - Raw sockets  │   - TTL manipulation       │
│  - Loss calc │   - Packet build │   - Hop discovery          │
│  - Avg/Min/  │   - Checksum     │   - Route mapping          │
│    Max       │   - DNS resolve  │   - Reverse DNS            │
│              │   - probe_host() │                            │
└──────────────┴──────────────────┴────────────────────────────┘
                        ▲
                        │
              ┌─────────┴─────────┐
              │   RAW ICMP SOCKET │
              │  (SOCK_RAW +      │
              │   IPPROTO_ICMP)   │
              └───────────────────┘
```

---

## 📦 File Structure

```
icmp_suite/
├── core/
│   ├── __init__.py           ← Package exports
│   ├── icmp_core.py          ← MAIN DELIVERABLE (Python 3.10+)
│   ├── icmp_core.c           ← C reference implementation
│   ├── icmp_core.h           ← C header file
│   └── checksum.py           ← Standalone RFC 1071 checksum utility
├── frontend/
│   └── dashboard.html        ← Terminal-style diagnostic dashboard (single file)
├── tests/
│   └── test_icmp_core.py     ← pytest unit tests (18 tests)
└── README.md                 ← This file
```

---

## ✅ Prerequisites

| Requirement | Version | Notes |
|------------|---------|-------|
| **Python** | 3.10+ | `from __future__ import annotations` used |
| **OS** | Linux / macOS | Windows raw sockets not supported |
| **Privileges** | `root` / `sudo` | Required for `SOCK_RAW` |
| **GCC** | Any recent | For C optional compilation |
| **pytest** | Any | For running unit tests |

> **No `pip` packages required** — the entire Python module uses stdlib only (`socket`, `struct`, `select`, `time`, `os`, `dataclasses`).

---

## 🚀 Quick Start

### Python — Single Probe

```bash
sudo python3 -c "
from core.icmp_core import probe_host
result = probe_host('8.8.8.8')
print(f'Reply from {result.responding_host} — RTT: {result.rtt_ms}ms')
"
```

### Python — CLI Mode

```bash
sudo python3 -m core.icmp_core google.com --ttl 64 --timeout 2
```

### Compile & Run C Implementation

```bash
cd core/
gcc -Wall -Wextra -std=c11 -O2 -o icmp_core icmp_core.c
sudo ./icmp_core google.com 5
```

### Run Tests (no root needed)

```bash
cd icmp_suite/
python -m pytest tests/test_icmp_core.py -v
```

### Open Dashboard

```
Open frontend/dashboard.html in any browser → click "▶ DEMO"
```

---

## 📡 Module API Reference

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ICMP_ECHO_REQUEST` | `8` | Echo Request type |
| `ICMP_ECHO_REPLY` | `0` | Echo Reply type |
| `ICMP_TIME_EXCEEDED` | `11` | TTL expired (traceroute) |
| `ICMP_DEST_UNREACH` | `3` | Destination unreachable |
| `DEFAULT_TIMEOUT` | `2.0` | Seconds |
| `DEFAULT_PACKET_SIZE` | `64` | Bytes |
| `DEFAULT_TTL` | `64` | Standard TTL |
| `MAX_HOPS` | `30` | Max traceroute hops |

### Data Classes

```python
@dataclass
class ICMPPacket:
    type, code, checksum, identifier, sequence, payload, raw

@dataclass
class ProbeResult:
    destination, resolved_ip, ttl, sequence, rtt_ms,
    received, icmp_type, icmp_code, responding_host, error
```

### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `calculate_checksum` | `(data: bytes) → int` | RFC 1071 Internet Checksum |
| `build_icmp_packet` | `(type, code, id, seq, size) → bytes` | Construct raw ICMP packet |
| `create_raw_socket` | `(family, timeout) → socket` | Create SOCK_RAW ICMP socket |
| `set_socket_ttl` | `(sock, ttl) → None` | Set IP TTL for traceroute |
| `send_icmp_packet` | `(sock, ip, packet) → float` | Send packet, return timestamp |
| `receive_icmp_reply` | `(sock, id, seq, timeout) → tuple\|None` | Wait for ICMP reply |
| `parse_icmp_packet` | `(raw: bytes) → ICMPPacket` | Parse raw ICMP bytes |
| `resolve_hostname` | `(hostname: str) → str` | DNS resolution with cache |
| `reverse_dns_lookup` | `(ip: str) → str` | Reverse DNS (never raises) |
| **`probe_host`** | `(dest, ttl, seq, ...) → ProbeResult` | **Main entry point** ⭐ |

---

## 🔌 Integration Contract — For Teammates

### Person 2 (Ping) — How to Use

```python
from core.icmp_core import probe_host, DEFAULT_TTL

results = []
for i in range(1, count + 1):
    result = probe_host("google.com", ttl=DEFAULT_TTL, sequence=i)
    results.append(result)

    if result.received:
        print(f"[SEQ {i}] Reply from {result.responding_host} — RTT: {result.rtt_ms:.3f}ms")
    else:
        print(f"[SEQ {i}] TIMEOUT ✗")

# Compute stats from results list: avg, min, max, loss%, jitter
```

### Person 3 (Traceroute) — How to Use

```python
from core.icmp_core import probe_host, ICMP_TIME_EXCEEDED, MAX_HOPS

for ttl in range(1, MAX_HOPS + 1):
    result = probe_host("google.com", ttl=ttl, sequence=ttl)

    if result.received:
        print(f"Hop {ttl}: {result.responding_host} — {result.rtt_ms:.3f}ms")
    else:
        print(f"Hop {ttl}: * * * (timeout)")

    # Stop when we reach the destination (type != Time Exceeded)
    if result.icmp_type is not None and result.icmp_type != ICMP_TIME_EXCEEDED:
        print("Destination reached!")
        break
```

---

## 🧪 Test Coverage

```
tests/test_icmp_core.py
├── TestChecksum (4 tests)
│   ├── test_checksum_known_value      — verify with known ICMP packet
│   ├── test_checksum_zero_data        — b'\x00\x00' → 0xFFFF
│   ├── test_checksum_odd_length       — odd-byte padding
│   └── test_checksum_all_ones         — b'\xff\xff' → 0x0000
├── TestBuildPacket (3 tests)
│   ├── test_build_icmp_packet_structure — length, type, checksum
│   ├── test_build_packet_identifier_and_sequence — ID/seq packing
│   └── test_build_packet_has_valid_checksum — self-validation
├── TestParsePacket (2 tests)
│   ├── test_parse_echo_reply          — parse Echo Reply
│   └── test_parse_too_short_raises    — ValueError on short data
├── TestDNS (3 tests)
│   ├── test_resolve_hostname_localhost — localhost → 127.0.0.1
│   ├── test_resolve_invalid_hostname  — raises ValueError
│   └── test_resolve_ip_passthrough    — IP string unchanged
├── TestDataStructures (3 tests)
│   ├── test_probe_result_dataclass    — all fields accessible
│   ├── test_probe_result_timeout      — None/False for timeout
│   └── test_icmp_packet_dataclass     — field validation
├── TestIdentifier (2 tests)
│   ├── test_packet_identifier_range   — PID & 0xFFFF in [0, 65535]
│   └── test_identifier_in_built_packet — ID matches in packet
└── TestStandaloneChecksum (1 test)
    └── test_import_and_compute        — standalone module works
```

---

## 📜 License

Educational project — Computer Networks Mini Project.

---

*Built with raw sockets, no shortcuts. 🛠️*
