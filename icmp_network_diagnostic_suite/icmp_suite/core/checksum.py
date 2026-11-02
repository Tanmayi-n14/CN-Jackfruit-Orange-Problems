#!/usr/bin/env python3
"""
checksum.py — Standalone Internet Checksum Utility
=====================================================

Provides the RFC 1071 Internet Checksum implementation as a standalone
importable utility.  This is the same algorithm used in ``icmp_core.py``
but exposed independently so it can be used for other protocols (TCP, UDP,
IP header checksum, etc.) or for testing purposes.

Usage::

    from core.checksum import internet_checksum, verify_checksum

    chk = internet_checksum(my_data)
    assert verify_checksum(my_data_with_checksum)

Reference: https://www.rfc-editor.org/rfc/rfc1071
"""

from __future__ import annotations


def internet_checksum(data: bytes) -> int:
    """
    Compute the RFC 1071 Internet Checksum over *data*.

    Algorithm
    ---------
    1. Treat *data* as a sequence of 16-bit big-endian words.
    2. Sum all words using 32-bit arithmetic.
    3. If the data has an **odd** length, pad with a trailing zero byte.
    4. Fold any carry (bits 16+) back into the lower 16 bits, repeating
       until no carry remains.
    5. Return the **one's complement** of the final 16-bit sum.

    Parameters
    ----------
    data : bytes
        Raw bytes to checksum.

    Returns
    -------
    int
        16-bit checksum value (0x0000 – 0xFFFF).

    Examples
    --------
    >>> internet_checksum(b'\\x00\\x00')
    65535
    >>> hex(internet_checksum(b'\\x00\\x01\\x00\\x02'))
    '0xfffc'
    """
    # Pad to even length.
    if len(data) % 2 != 0:
        data += b'\x00'

    # Sum consecutive 16-bit words (big-endian).
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        total += word

    # Fold carries until the sum fits in 16 bits.
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    # One's complement.
    return ~total & 0xFFFF


def verify_checksum(data: bytes) -> bool:
    """
    Verify that *data* (which includes an embedded checksum) is valid.

    If the checksum is correct, computing the Internet Checksum over the
    *entire* block (including the embedded checksum field) yields 0 or
    0xFFFF (depending on implementation).  We accept either as valid.

    Parameters
    ----------
    data : bytes
        Data block with embedded checksum.

    Returns
    -------
    bool
        ``True`` if the checksum is valid.
    """
    result = internet_checksum(data)
    # A valid checksum over the entire data (including the checksum field)
    # should yield 0x0000 (when treated as one's complement sum) or 0xFFFF.
    return result == 0x0000 or result == 0xFFFF


# ── CLI helper ────────────────────────────────────────────────────────

if __name__ == '__main__':
    import sys

    if len(sys.argv) < 2:
        print("Usage: python checksum.py <hex_string>")
        print("Example: python checksum.py 080000000001000148656c6c6f")
        sys.exit(1)

    raw = bytes.fromhex(sys.argv[1])
    chk = internet_checksum(raw)
    print(f"Data   : {raw.hex()}")
    print(f"Checksum: 0x{chk:04X} ({chk})")
    print(f"Valid  : {verify_checksum(raw)}")
