#!/usr/bin/env python3
"""
icmp_core.py — ICMP Raw Socket Core Module
============================================

The foundational building block for a combined Ping + Traceroute diagnostic suite.
Uses raw ICMP sockets — no calls to system ping/traceroute binaries.

This module provides:
  - ICMP packet construction and parsing (RFC 792)
  - Raw socket creation with TTL control
  - Probe sending + reply reception with RTT measurement
  - DNS resolution utilities

Integration Contract
--------------------
  Person 2 (Ping):
      from core.icmp_core import probe_host, DEFAULT_TTL
      result = probe_host("google.com", ttl=64, sequence=i)

  Person 3 (Traceroute):
      from core.icmp_core import probe_host, ICMP_TIME_EXCEEDED, MAX_HOPS
      for ttl in range(1, MAX_HOPS + 1):
          result = probe_host("google.com", ttl=ttl, sequence=ttl)
          if result.icmp_type != ICMP_TIME_EXCEEDED:
              break

Author : Person 1 (Core Module)
Python : 3.10+  (stdlib only — no pip dependencies)
Platform: Linux / macOS (requires root / sudo for raw sockets)
"""

from __future__ import annotations

import os
import socket
import struct
import select
import time
import sys
from dataclasses import dataclass, field

# ════════════════════════════════════════════════════════════════════════
#  ICMP PROTOCOL CONSTANTS  (RFC 792)
# ════════════════════════════════════════════════════════════════════════
#
#  ICMP message types relevant to ping / traceroute:
#
#    Type 8  — Echo Request   (what we send)
#    Type 0  — Echo Reply     (successful ping reply)
#    Type 11 — Time Exceeded  (TTL expired in transit — used by traceroute)
#    Type 3  — Destination Unreachable (host/network unreachable)
#

ICMP_ECHO_REQUEST: int = 8     # We send this to request an echo
ICMP_ECHO_REPLY: int = 0       # Target replies with this on success
ICMP_TIME_EXCEEDED: int = 11   # Router replies with this when TTL hits 0
ICMP_DEST_UNREACH: int = 3     # Router/host replies when dest is unreachable

# ─── Default configuration ───────────────────────────────────────────
DEFAULT_TIMEOUT: float = 2.0          # Seconds to wait for a reply
DEFAULT_PACKET_SIZE: int = 64         # Total ICMP packet size in bytes
DEFAULT_TTL: int = 64                 # Standard Time-To-Live for ping
MAX_HOPS: int = 30                    # Maximum hops for traceroute
ICMP_HEADER_SIZE: int = 8             # ICMP header is always 8 bytes


# ════════════════════════════════════════════════════════════════════════
#  DATA STRUCTURES
# ════════════════════════════════════════════════════════════════════════

@dataclass
class ICMPPacket:
    """
    Parsed representation of a received ICMP packet.

    Fields
    ------
    type       : ICMP message type  (0 = reply, 8 = request, 11 = time exceeded …)
    code       : Sub-type code      (varies per type, usually 0)
    checksum   : 16-bit Internet checksum from the ICMP header
    identifier : Echo ID used to match requests ↔ replies
    sequence   : Sequence number for ordering
    payload    : Raw payload bytes (after the 8-byte header)
    raw        : Complete raw bytes as received (including header)
    """

    type: int
    code: int
    checksum: int
    identifier: int
    sequence: int
    payload: bytes
    raw: bytes


@dataclass
class ProbeResult:
    """
    Complete result of a single ICMP probe.

    This is the primary data object exchanged between the core module
    and the ping / traceroute modules.

    Fields
    ------
    destination      : Original hostname / IP the user requested
    resolved_ip      : Actual IPv4 address after DNS resolution
    ttl              : TTL value that was set on the outbound socket
    sequence         : Sequence number of this probe
    rtt_ms           : Round-trip time in milliseconds, or None on timeout
    received         : True if any reply was received before timeout
    icmp_type        : ICMP type of the reply (0, 3, 11 …) or None
    icmp_code        : ICMP code of the reply, or None
    responding_host  : IP address of the host that actually replied
                       (differs from resolved_ip for intermediate routers)
    error            : Human-readable error string, or None
    """

    destination: str
    resolved_ip: str
    ttl: int
    sequence: int
    rtt_ms: float | None        # None ⇒ timeout
    received: bool
    icmp_type: int | None
    icmp_code: int | None
    responding_host: str | None
    error: str | None


# ════════════════════════════════════════════════════════════════════════
#  MODULE-LEVEL DNS CACHE
# ════════════════════════════════════════════════════════════════════════
# Avoids hammering the resolver when probing the same host in a loop.

_dns_cache: dict[str, str] = {}


# ════════════════════════════════════════════════════════════════════════
#  1. CHECKSUM
# ════════════════════════════════════════════════════════════════════════

def calculate_checksum(data: bytes) -> int:
    """
    Compute the **RFC 1071 Internet Checksum** over *data*.

    Algorithm (from RFC 1071 §4.1):
      1. Treat the data as a sequence of 16-bit (2-byte) words, big-endian.
      2. Sum all 16-bit words using unsigned 32-bit arithmetic.
      3. If the data has an odd number of bytes, pad with one zero byte at
         the end before summing the final 16-bit word.
      4. Fold any carry bits (bits above the low 16) back into the sum
         repeatedly until no carry remains.
      5. Return the one's complement of the final 16-bit sum (~sum & 0xFFFF).

    This checksum is used in the ICMP header's ``checksum`` field.  The sender
    sets checksum = 0, computes calculate_checksum() over the entire ICMP
    message (header + payload), and writes the result back into the header.
    The receiver performs the same computation over the received message; if the
    result is 0xFFFF the packet is valid.

    Parameters
    ----------
    data : bytes
        Raw bytes over which to compute the checksum.

    Returns
    -------
    int
        16-bit Internet checksum.
    """
    # If the data length is odd, pad with a trailing zero byte so we can
    # process everything as 16-bit words.
    if len(data) % 2 != 0:
        data += b'\x00'

    # Sum 16-bit words.  struct.unpack is used to pull unsigned shorts in
    # network byte order (big-endian, '!').
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word

    # Fold 32-bit sum into 16 bits by adding the carry (upper 16 bits) back.
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # One's complement — flip all bits and mask to 16 bits.
    checksum = ~checksum & 0xFFFF
    return checksum


# ════════════════════════════════════════════════════════════════════════
#  2. BUILD ICMP PACKET
# ════════════════════════════════════════════════════════════════════════

def build_icmp_packet(
    icmp_type: int,
    icmp_code: int,
    identifier: int,
    sequence: int,
    payload_size: int = DEFAULT_PACKET_SIZE,
) -> bytes:
    """
    Construct a raw ICMP Echo Request packet ready to send on the wire.

    ICMP Echo Request/Reply header layout (8 bytes):
    ::

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Type      |     Code      |          Checksum             |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |           Identifier          |        Sequence Number        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Payload ...                                               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    The payload embeds a high-precision timestamp (``struct.pack('d', time.time())``)
    in the first 8 bytes, followed by repeating ``b'Q'`` fill bytes.

    Parameters
    ----------
    icmp_type    : ICMP message type (8 for Echo Request).
    icmp_code    : ICMP code (usually 0).
    identifier   : 16-bit ID to match request ↔ reply (typically ``os.getpid() & 0xFFFF``).
    sequence     : 16-bit sequence number.
    payload_size : Total ICMP packet size including header (default 64 bytes).
                   The actual payload will be ``payload_size - ICMP_HEADER_SIZE`` bytes.

    Returns
    -------
    bytes
        Complete ICMP packet (header + payload) with a valid checksum.
    """
    # ── Step 1: Build the header with checksum = 0 ────────────────────
    # Format '!BBHHH' = network byte order:
    #   B = unsigned char  (Type, Code)
    #   H = unsigned short (Checksum, Identifier, Sequence)
    header = struct.pack(
        '!BBHHH',
        icmp_type,                 # 1 byte  — Type
        icmp_code,                 # 1 byte  — Code
        0,                         # 2 bytes — Checksum (placeholder)
        identifier & 0xFFFF,       # 2 bytes — Identifier
        sequence & 0xFFFF,         # 2 bytes — Sequence
    )

    # ── Step 2: Build the payload ──────────────────────────────────────
    # Payload size = total packet size − 8-byte header.
    payload_bytes_needed = max(payload_size - ICMP_HEADER_SIZE, 0)

    # Embed a double-precision timestamp in the first 8 bytes of payload
    # so the receiver can calculate RTT without tracking state externally.
    timestamp_bytes = struct.pack('!d', time.time())  # 8 bytes, network order

    if payload_bytes_needed >= len(timestamp_bytes):
        # Fill remaining payload with repeating 'Q' bytes.
        fill_length = payload_bytes_needed - len(timestamp_bytes)
        payload = timestamp_bytes + (b'Q' * fill_length)
    else:
        # Edge case: payload_size is smaller than timestamp — truncate.
        payload = timestamp_bytes[:payload_bytes_needed]

    # ── Step 3: Compute checksum over (header + payload) ──────────────
    packet_without_checksum = header + payload
    chk = calculate_checksum(packet_without_checksum)

    # ── Step 4: Re-pack the header with the real checksum ─────────────
    header = struct.pack(
        '!BBHHH',
        icmp_type,
        icmp_code,
        chk,
        identifier & 0xFFFF,
        sequence & 0xFFFF,
    )

    return header + payload


# ════════════════════════════════════════════════════════════════════════
#  3. CREATE RAW SOCKET
# ════════════════════════════════════════════════════════════════════════

def create_raw_socket(
    family: int = socket.AF_INET,
    timeout: float = DEFAULT_TIMEOUT,
) -> socket.socket:
    """
    Create and configure a raw ICMP socket.

    Raw sockets allow us to craft our own ICMP packets from scratch instead
    of relying on the kernel's ping implementation.  This gives us full
    control over TTL, payload, timing, and reply parsing.

    Socket options set:
      - ``IP_HDRINCL = 0``   → let the kernel fill in the IP header for us.
      - Receive timeout       → avoid blocking forever on ``recvfrom()``.

    Platform notes:
      - **Linux / macOS**: Requires ``root`` or ``CAP_NET_RAW``.
      - **Windows**: Raw ICMP sockets behave differently; not supported here.

    Parameters
    ----------
    family  : Address family (default ``AF_INET`` for IPv4).
    timeout : Socket receive timeout in seconds (default 2.0).

    Returns
    -------
    socket.socket
        Configured raw ICMP socket ready for ``sendto()`` / ``recvfrom()``.

    Raises
    ------
    PermissionError
        If the process lacks privileges to create a raw socket.
    OSError
        On any other socket creation failure.
    """
    # ── Platform guard ────────────────────────────────────────────────
    if sys.platform == 'win32':
        raise NotImplementedError(
            "Raw ICMP sockets on Windows require special handling not "
            "covered by this module.  Run on Linux or macOS."
        )

    # ── Create raw socket ─────────────────────────────────────────────
    try:
        sock = socket.socket(
            family,
            socket.SOCK_RAW,
            socket.IPPROTO_ICMP,
        )
    except PermissionError:
        raise PermissionError(
            "Cannot create raw ICMP socket — permission denied.\n"
            "  → On Linux / macOS run with:  sudo python3 your_script.py\n"
            "  → Or grant capability:        sudo setcap cap_net_raw+ep $(which python3)"
        )
    except OSError as exc:
        raise OSError(f"Failed to create raw ICMP socket: {exc}") from exc

    # ── Set receive timeout ───────────────────────────────────────────
    # Convert float seconds to a struct timeval (seconds, microseconds)
    # used by SO_RCVTIMEO.
    timeout_sec = int(timeout)
    timeout_usec = int((timeout - timeout_sec) * 1_000_000)
    timeval = struct.pack('ll', timeout_sec, timeout_usec)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeval)

    # ── Do NOT include IP header in our packet (let kernel add it) ────
    # IP_HDRINCL = 0 means the kernel prepends a valid IP header for us.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)

    return sock


# ════════════════════════════════════════════════════════════════════════
#  4. SET SOCKET TTL
# ════════════════════════════════════════════════════════════════════════

def set_socket_ttl(sock: socket.socket, ttl: int) -> None:
    """
    Set the IP Time-To-Live (TTL) on an outbound socket.

    TTL controls how many routers (hops) a packet can traverse before being
    discarded.  Each router decrements the TTL by 1; when it reaches 0 the
    router drops the packet and sends back an ICMP **Time Exceeded** (type 11)
    message.  This mechanism is the basis of ``traceroute``:

      - TTL=1 → the **first** hop router replies with Time Exceeded
      - TTL=2 → the **second** hop replies
      - TTL=N → destination (or Nth hop) replies

    For a normal ``ping`` we typically set TTL=64 or TTL=128.

    Parameters
    ----------
    sock : socket.socket
        An open raw ICMP socket.
    ttl  : int
        TTL value to set (valid range: 1–255).

    Raises
    ------
    ValueError
        If *ttl* is outside the 1–255 range.
    """
    if not (1 <= ttl <= 255):
        raise ValueError(f"TTL must be between 1 and 255, got {ttl}")

    # IP_TTL is an IP-level socket option that sets the Time-To-Live field
    # in every outgoing IP packet on this socket.
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)


# ════════════════════════════════════════════════════════════════════════
#  5. SEND ICMP PACKET
# ════════════════════════════════════════════════════════════════════════

def send_icmp_packet(
    sock: socket.socket,
    destination_ip: str,
    packet: bytes,
    port: int = 0,
) -> float:
    """
    Transmit a raw ICMP packet to *destination_ip* and return the send timestamp.

    Uses ``sock.sendto()`` to push the pre-built ICMP bytes onto the network.
    The IP header is added automatically by the kernel (see ``create_raw_socket``).

    A high-resolution ``time.perf_counter()`` timestamp is recorded immediately
    after ``sendto()`` returns; this is later compared with the receive timestamp
    to compute RTT.

    Parameters
    ----------
    sock           : Open raw ICMP socket.
    destination_ip : Dotted-decimal IPv4 address (e.g. ``"142.250.80.46"``).
    packet         : Raw ICMP bytes (from ``build_icmp_packet()``).
    port           : Destination port (always 0 for ICMP; kept for API consistency).

    Returns
    -------
    float
        ``time.perf_counter()`` value at send time.

    Raises
    ------
    OSError
        If ``sendto()`` fails (e.g. network down, invalid address).
    """
    sock.sendto(packet, (destination_ip, port))
    send_time = time.perf_counter()
    return send_time


# ════════════════════════════════════════════════════════════════════════
#  6. RECEIVE ICMP REPLY
# ════════════════════════════════════════════════════════════════════════

def receive_icmp_reply(
    sock: socket.socket,
    expected_id: int,
    expected_seq: int,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[bytes, str, float] | None:
    """
    Wait for an ICMP reply and return the raw data, sender IP, and timestamp.

    Uses ``select.select()`` for portable timeout handling (works on both
    Linux and macOS without relying solely on ``SO_RCVTIMEO``).

    Packet validation logic:
      - **ICMP Echo Reply (type 0)**: Verify that the Identifier and Sequence
        fields match the values we sent.  This is needed because the kernel may
        deliver replies for *other* ping processes running on the same host.
      - **ICMP Time Exceeded (type 11)**: Accept immediately — traceroute
        depends on these.  The original request header is embedded in the
        payload, but we don't filter on it here for simplicity.
      - **ICMP Destination Unreachable (type 3)**: Accept immediately.

    IP header note:
      ``recvfrom()`` on a raw socket returns the **entire** IP datagram,
      including the 20-byte IP header.  We skip it when parsing ICMP data.

    Parameters
    ----------
    sock         : Open raw ICMP socket.
    expected_id  : The Identifier we used in the outbound Echo Request.
    expected_seq : The Sequence number we used in the outbound request.
    timeout      : Seconds to wait before giving up.

    Returns
    -------
    tuple[bytes, str, float] | None
        ``(raw_packet, sender_ip, recv_timestamp)`` on success, or
        ``None`` if the timeout expires or no matching reply is received.
    """
    # Loop to skip irrelevant packets (other processes' pings, etc.)
    deadline = time.perf_counter() + timeout

    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            return None  # Overall timeout expired

        # ── Wait for the socket to become readable ────────────────────
        ready = select.select([sock], [], [], remaining)
        if not ready[0]:
            return None  # Timeout — no data arrived

        # ── Receive the raw IP datagram ───────────────────────────────
        try:
            raw_data, addr = sock.recvfrom(1024)
        except socket.timeout:
            return None
        except OSError:
            return None

        recv_time = time.perf_counter()

        # addr is a tuple (ip_string, port); extract the IP.
        sender_ip = addr[0]

        # ── Strip the 20-byte IP header to get ICMP data ─────────────
        #
        #  IP Header (simplified):
        #  ┌──────────┬──────────┬────────────────────────────────────┐
        #  │ 0-3      │ 4-7      │ 8-19                              │
        #  │ Ver+IHL  │ TOS      │ Length, ID, Flags, TTL, Proto … │
        #  └──────────┴──────────┴────────────────────────────────────┘
        #  ICMP data starts at byte 20.
        #
        if len(raw_data) < 28:
            # Packet too short to contain IP header + ICMP header — skip.
            continue

        # Extract the IP header length from the IHL field (lower nibble of byte 0).
        # IHL is in units of 4 bytes.  Usually IHL=5 → 20 bytes.
        ip_header_len = (raw_data[0] & 0x0F) * 4
        icmp_data = raw_data[ip_header_len:]

        if len(icmp_data) < ICMP_HEADER_SIZE:
            continue

        # ── Parse the ICMP type from byte 0 ──────────────────────────
        icmp_type = icmp_data[0]

        if icmp_type == ICMP_ECHO_REPLY:
            # Echo Reply — verify ID and Sequence match ours.
            # ID is at ICMP offset 4-6, Sequence at 6-8 (network byte order).
            reply_id = struct.unpack('!H', icmp_data[4:6])[0]
            reply_seq = struct.unpack('!H', icmp_data[6:8])[0]

            if reply_id != (expected_id & 0xFFFF):
                continue  # Not our packet — keep waiting
            if reply_seq != (expected_seq & 0xFFFF):
                continue

            return (raw_data, sender_ip, recv_time)

        elif icmp_type == ICMP_TIME_EXCEEDED:
            # Time Exceeded — a router along the path dropped our packet
            # because TTL reached 0.  The original IP header + first 8 bytes
            # of our ICMP request are embedded in the Time Exceeded payload.
            #
            # Layout of Time Exceeded message:
            #   Bytes 0-7  : Time Exceeded ICMP header
            #   Bytes 8-27 : Original IP header (20 bytes)
            #   Bytes 28-35: First 8 bytes of original ICMP request ← our ID+Seq
            #
            # We extract the original ID from offset 32-34 (relative to icmp_data)
            # to ensure this is our packet, not someone else's.
            if len(icmp_data) >= 36:
                orig_id = struct.unpack('!H', icmp_data[32:34])[0]
                orig_seq = struct.unpack('!H', icmp_data[34:36])[0]
                if orig_id == (expected_id & 0xFFFF) and orig_seq == (expected_seq & 0xFFFF):
                    return (raw_data, sender_ip, recv_time)
                else:
                    continue  # Not our packet
            else:
                # Malformed, but still a Time Exceeded — return it.
                return (raw_data, sender_ip, recv_time)

        elif icmp_type == ICMP_DEST_UNREACH:
            # Destination Unreachable — the host or network is unreachable.
            # Accept immediately.
            return (raw_data, sender_ip, recv_time)

        else:
            # Unrelated ICMP type — ignore and keep waiting.
            continue


# ════════════════════════════════════════════════════════════════════════
#  7. PARSE ICMP PACKET
# ════════════════════════════════════════════════════════════════════════

def parse_icmp_packet(raw_data: bytes) -> ICMPPacket:
    """
    Parse raw ICMP bytes (IP header **already stripped**) into an ``ICMPPacket``.

    Header layout (8 bytes, network byte order):
    ::

        struct.unpack('!BBHHH', raw_data[:8])
        ─────────────  ─ ─ ── ── ──
                        │ │  │  │  └─ Sequence (2 bytes)
                        │ │  │  └──── Identifier (2 bytes)
                        │ │  └─────── Checksum (2 bytes)
                        │ └────────── Code (1 byte)
                        └─────────── Type (1 byte)

    Parameters
    ----------
    raw_data : bytes
        ICMP packet bytes **without** the IP header prefix.

    Returns
    -------
    ICMPPacket
        Populated dataclass with all parsed fields.
    """
    if len(raw_data) < ICMP_HEADER_SIZE:
        raise ValueError(
            f"ICMP data too short: {len(raw_data)} bytes (need >= {ICMP_HEADER_SIZE})"
        )

    # Unpack the 8-byte ICMP header.
    icmp_type, icmp_code, checksum, identifier, sequence = struct.unpack(
        '!BBHHH', raw_data[:ICMP_HEADER_SIZE]
    )

    payload = raw_data[ICMP_HEADER_SIZE:]

    return ICMPPacket(
        type=icmp_type,
        code=icmp_code,
        checksum=checksum,
        identifier=identifier,
        sequence=sequence,
        payload=payload,
        raw=raw_data,
    )


# ════════════════════════════════════════════════════════════════════════
#  8. DNS RESOLUTION
# ════════════════════════════════════════════════════════════════════════

def resolve_hostname(hostname: str) -> str:
    """
    Resolve a hostname to an IPv4 address, with caching.

    Results are cached in a module-level ``_dns_cache`` dict so that
    repeated probes to the same host (as in a ping loop) don't hammer
    the system resolver.

    Parameters
    ----------
    hostname : str
        Hostname or IP address string (e.g. ``"google.com"`` or ``"8.8.8.8"``).

    Returns
    -------
    str
        Dotted-decimal IPv4 address.

    Raises
    ------
    ValueError
        If DNS resolution fails.
    """
    # Return cached result if available.
    if hostname in _dns_cache:
        return _dns_cache[hostname]

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        raise ValueError(
            f"Cannot resolve hostname '{hostname}': {exc}"
        ) from exc

    _dns_cache[hostname] = ip
    return ip


# ════════════════════════════════════════════════════════════════════════
#  9. REVERSE DNS LOOKUP
# ════════════════════════════════════════════════════════════════════════

def reverse_dns_lookup(ip: str) -> str:
    """
    Reverse DNS lookup — convert an IP address to a hostname.

    Used by traceroute to show friendly names for intermediate routers.
    Never raises: returns the raw IP string if the lookup fails (many routers
    have no PTR record).

    Parameters
    ----------
    ip : str
        Dotted-decimal IPv4 address.

    Returns
    -------
    str
        Hostname string, or *ip* itself on failure.
    """
    try:
        # gethostbyaddr returns (hostname, aliases, addresses).
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        # Lookup failed — this is common for routers without PTR records.
        return ip


# ════════════════════════════════════════════════════════════════════════
#  10. PROBE HOST — THE MAIN PUBLIC INTERFACE
# ════════════════════════════════════════════════════════════════════════

def probe_host(
    destination: str,
    ttl: int = DEFAULT_TTL,
    sequence: int = 1,
    payload_size: int = DEFAULT_PACKET_SIZE,
    timeout: float = DEFAULT_TIMEOUT,
    identifier: int | None = None,
) -> ProbeResult:
    """
    Send **one** ICMP Echo Request and return the full result.

    This is the **primary entry point** for the entire ICMP core module.
    Person 2 (Ping) and Person 3 (Traceroute) call this in a loop.

    Workflow
    --------
    1. Resolve *destination* to an IPv4 address.
    2. Create a raw ICMP socket.
    3. Set the socket's TTL.
    4. Build an ICMP Echo Request packet.
    5. Send the packet and record the send timestamp.
    6. Wait for a reply (Echo Reply, Time Exceeded, or Dest Unreachable).
    7. Close the socket.
    8. Compute RTT and return a ``ProbeResult``.

    Usage — Ping (Person 2)::

        for i in range(1, count + 1):
            result = probe_host("google.com", ttl=64, sequence=i)
            if result.received:
                print(f"Reply: {result.rtt_ms:.3f} ms")

    Usage — Traceroute (Person 3)::

        for hop in range(1, MAX_HOPS + 1):
            result = probe_host("google.com", ttl=hop, sequence=hop)
            print(f"Hop {hop}: {result.responding_host} {result.rtt_ms} ms")
            if result.icmp_type != ICMP_TIME_EXCEEDED:
                break

    Parameters
    ----------
    destination  : Hostname or IPv4 address to probe.
    ttl          : IP Time-To-Live value (1–255).
    sequence     : ICMP sequence number for this probe.
    payload_size : Total ICMP packet size in bytes (including header).
    timeout      : Seconds to wait for a reply.
    identifier   : Optional ICMP Identifier override (defaults to PID-based).

    Returns
    -------
    ProbeResult
        Fully populated result with RTT, ICMP type/code, responding host, etc.
    """
    # ── Step 1: Resolve hostname ──────────────────────────────────────
    try:
        resolved_ip = resolve_hostname(destination)
    except ValueError as exc:
        return ProbeResult(
            destination=destination,
            resolved_ip="",
            ttl=ttl,
            sequence=sequence,
            rtt_ms=None,
            received=False,
            icmp_type=None,
            icmp_code=None,
            responding_host=None,
            error=str(exc),
        )

    # ── Step 2: Choose an identifier ──────────────────────────────────
    if identifier is None:
        identifier = os.getpid() & 0xFFFF

    # ── Step 3–8: Socket lifecycle ────────────────────────────────────
    sock = None
    try:
        # Create socket
        sock = create_raw_socket(timeout=timeout)

        # Set TTL (critical for traceroute)
        set_socket_ttl(sock, ttl)

        # Build the ICMP Echo Request packet
        packet = build_icmp_packet(
            icmp_type=ICMP_ECHO_REQUEST,
            icmp_code=0,
            identifier=identifier,
            sequence=sequence,
            payload_size=payload_size,
        )

        # Send the packet and record the high-resolution send time
        send_time = send_icmp_packet(sock, resolved_ip, packet)

        # Wait for a reply
        result = receive_icmp_reply(sock, identifier, sequence, timeout)

    except PermissionError as exc:
        return ProbeResult(
            destination=destination,
            resolved_ip=resolved_ip,
            ttl=ttl,
            sequence=sequence,
            rtt_ms=None,
            received=False,
            icmp_type=None,
            icmp_code=None,
            responding_host=None,
            error=str(exc),
        )
    except OSError as exc:
        return ProbeResult(
            destination=destination,
            resolved_ip=resolved_ip,
            ttl=ttl,
            sequence=sequence,
            rtt_ms=None,
            received=False,
            icmp_type=None,
            icmp_code=None,
            responding_host=None,
            error=f"OS error during probe: {exc}",
        )
    finally:
        if sock is not None:
            sock.close()

    # ── Handle timeout ────────────────────────────────────────────────
    if result is None:
        return ProbeResult(
            destination=destination,
            resolved_ip=resolved_ip,
            ttl=ttl,
            sequence=sequence,
            rtt_ms=None,
            received=False,
            icmp_type=None,
            icmp_code=None,
            responding_host=None,
            error=None,
        )

    # ── Parse the reply ───────────────────────────────────────────────
    recv_data, sender_ip, recv_time = result

    # RTT = receive timestamp − send timestamp, converted to milliseconds.
    rtt_ms = (recv_time - send_time) * 1000.0

    # Strip IP header to get raw ICMP bytes for parsing.
    ip_header_len = (recv_data[0] & 0x0F) * 4
    icmp_bytes = recv_data[ip_header_len:]
    parsed = parse_icmp_packet(icmp_bytes)

    return ProbeResult(
        destination=destination,
        resolved_ip=resolved_ip,
        ttl=ttl,
        sequence=sequence,
        rtt_ms=round(rtt_ms, 3),
        received=True,
        icmp_type=parsed.type,
        icmp_code=parsed.code,
        responding_host=sender_ip,
        error=None,
    )


# ════════════════════════════════════════════════════════════════════════
#  MODULE SELF-TEST (when run directly)
# ════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description="ICMP Core Module — send a single probe to a host."
    )
    parser.add_argument('host', help="Hostname or IP address to probe")
    parser.add_argument('--ttl', type=int, default=DEFAULT_TTL, help="TTL value")
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, help="Timeout in seconds")
    args = parser.parse_args()

    print(f"[ICMP CORE] Probing {args.host} (TTL={args.ttl}, timeout={args.timeout}s)…")
    probe = probe_host(args.host, ttl=args.ttl, timeout=args.timeout)

    if probe.error:
        print(f"[ERROR] {probe.error}")
    elif probe.received:
        print(
            f"[REPLY] from {probe.responding_host} — "
            f"RTT={probe.rtt_ms:.3f}ms  type={probe.icmp_type}  code={probe.icmp_code}"
        )
    else:
        print("[TIMEOUT] No reply received.")
