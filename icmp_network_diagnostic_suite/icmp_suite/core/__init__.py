# ICMP Core Module
# This package provides low-level ICMP raw socket utilities for building
# network diagnostic tools (ping, traceroute) from scratch.
#
# Main entry point: probe_host() — sends a single ICMP probe and returns a ProbeResult.

from .icmp_core import (
    probe_host,
    ProbeResult,
    ICMPPacket,
    calculate_checksum,
    build_icmp_packet,
    create_raw_socket,
    set_socket_ttl,
    send_icmp_packet,
    receive_icmp_reply,
    parse_icmp_packet,
    resolve_hostname,
    reverse_dns_lookup,
    ICMP_ECHO_REQUEST,
    ICMP_ECHO_REPLY,
    ICMP_TIME_EXCEEDED,
    ICMP_DEST_UNREACH,
    DEFAULT_TIMEOUT,
    DEFAULT_PACKET_SIZE,
    DEFAULT_TTL,
    MAX_HOPS,
    ICMP_HEADER_SIZE,
)
