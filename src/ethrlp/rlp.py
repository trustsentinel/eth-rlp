"""RLP (Recursive Length Prefix) codec, focused on Ethereum's discv4
node-discovery packets.

Two layers are provided:

* Canonical byte-level RLP: :func:`encode` / :func:`decode`, operating on
  ``bytes`` and nested lists — the standard, round-trippable primitive.
* discv4 conveniences: :func:`decode_hex` and :func:`decode_neighbours_payload`,
  which take a hex string and produce hex-string trees / a friendly dict.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Union, cast

__all__ = [
    "encode",
    "decode",
    "decode_hex",
    "decode_neighbours_payload",
    "decode_expiration",
    "hex_to_ip",
    "hex_to_port",
]

# Canonical RLP item: a byte string, or a (possibly nested) list of items.
RLPItem = Union[bytes, list["RLPItem"]]
# decode_hex produces the same shape but with hex strings at the leaves.
HexTree = Union[str, list["HexTree"]]


# --------------------------------------------------------------------------- #
# Canonical byte-level RLP
# --------------------------------------------------------------------------- #
def _encode_length(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([offset + length])
    len_bytes = length.to_bytes((length.bit_length() + 7) // 8 or 1, "big")
    return bytes([offset + 55 + len(len_bytes)]) + len_bytes


def encode(item: RLPItem) -> bytes:
    """RLP-encode a byte string or a (nested) list of them."""
    if isinstance(item, (bytes, bytearray)):
        data = bytes(item)
        if len(data) == 1 and data[0] <= 0x7F:
            return data
        return _encode_length(len(data), 0x80) + data
    if isinstance(item, list):
        payload = b"".join(encode(x) for x in item)
        return _encode_length(len(payload), 0xC0) + payload
    raise TypeError(f"cannot RLP-encode value of type {type(item).__name__}")


def decode(data: bytes) -> RLPItem:
    """Decode a single, complete RLP item from ``data``."""
    item, consumed = _decode_item(bytes(data), 0)
    if consumed != len(data):
        raise ValueError("trailing bytes after RLP item")
    return item


def _decode_item(data: bytes, i: int) -> tuple[RLPItem, int]:
    if i >= len(data):
        raise ValueError("unexpected end of RLP input")
    prefix = data[i]
    if prefix <= 0x7F:  # single byte, itself
        return data[i : i + 1], i + 1
    if prefix <= 0xB7:  # short string
        n = prefix - 0x80
        start = i + 1
        return data[start : start + n], start + n
    if prefix <= 0xBF:  # long string
        ll = prefix - 0xB7
        n = int.from_bytes(data[i + 1 : i + 1 + ll], "big")
        start = i + 1 + ll
        return data[start : start + n], start + n
    if prefix <= 0xF7:  # short list
        n = prefix - 0xC0
        return _decode_list(data, i + 1, n)
    # long list
    ll = prefix - 0xF7
    n = int.from_bytes(data[i + 1 : i + 1 + ll], "big")
    return _decode_list(data, i + 1 + ll, n)


def _decode_list(data: bytes, start: int, length: int) -> tuple[list[RLPItem], int]:
    end = start + length
    if end > len(data):
        raise ValueError("RLP list length exceeds input")
    out: list[RLPItem] = []
    j = start
    while j < end:
        item, j = _decode_item(data, j)
        out.append(item)
    if j != end:
        raise ValueError("RLP list length mismatch")
    return out, end


# --------------------------------------------------------------------------- #
# discv4 conveniences (hex in, friendly out)
#
# These are intentionally LENIENT: real discv4 captures are often truncated, so
# unlike the strict canonical decode() above they best-effort over short input
# (matching the original behaviour) and keep hex strings at the leaves.
# --------------------------------------------------------------------------- #
def decode_hex(input_hex: str) -> list[HexTree]:
    """Best-effort decode of a hex RLP payload into a tree of hex strings."""

    def _decode(s: str, index: int = 0) -> tuple[list[HexTree], int]:
        output: list[HexTree] = []
        while index < len(s):
            prefix = int(s[index : index + 2], 16)
            if prefix <= 0x7F:  # single byte
                output.append(s[index : index + 2])
                index += 2
            elif 0x80 <= prefix <= 0xB7:  # short string
                length = prefix - 0x80
                index += 2
                output.append(s[index : index + 2 * length])
                index += 2 * length
            elif 0xB8 <= prefix <= 0xBF:  # long string
                len_of_len = prefix - 0xB7
                length = int(s[index + 2 : index + 2 + 2 * len_of_len], 16)
                index += 2 + 2 * len_of_len
                output.append(s[index : index + 2 * length])
                index += 2 * length
            elif 0xC0 <= prefix <= 0xF7:  # short list
                length = prefix - 0xC0
                index += 2
                sub, _ = _decode(s[index : index + 2 * length], 0)
                output.append(sub)
                index += 2 * length
            else:  # 0xF8..0xFF, long list
                len_of_len = prefix - 0xF7
                length = int(s[index + 2 : index + 2 + 2 * len_of_len], 16)
                index += 2 + 2 * len_of_len
                sub, _ = _decode(s[index : index + 2 * length], 0)
                output.append(sub)
                index += 2 * length
        return output, index

    decoded, _ = _decode(input_hex)
    return decoded


def decode_expiration(hex_str: str) -> str:
    """Format a hex UNIX timestamp as an ISO-like UTC string."""
    timestamp = int(hex_str, 16)
    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def hex_to_ip(hexstr: str) -> str:
    """Convert a hex-encoded IPv4 address (4 bytes) to dotted-quad."""
    return ".".join(str(int(hexstr[i : i + 2], 16)) for i in range(0, len(hexstr), 2))


def hex_to_port(hexstr: str) -> int:
    """Convert a hex-encoded port to an int (empty string → 0)."""
    if hexstr == "":
        return 0
    return int(hexstr, 16)


def decode_neighbours_payload(input_hex: str) -> dict[str, object]:
    """Decode a discv4 NEIGHBOURS packet payload into ``{neighbours, expiration}``.

    Each neighbour is ``{"host": "<ip>:<udp_port>", "port": <tcp_port>, "hash": <node_id>}``.
    """
    decoded = decode_hex(input_hex)
    neighbours: list[dict[str, object]] = []
    expiration = ""
    for value in decoded:
        if not isinstance(value, list):
            continue
        for entry in value:
            if not isinstance(entry, list):
                expiration = decode_expiration(entry)
                continue
            for node in entry:
                # A neighbour node is [ip, udp_port, tcp_port, node_id]; skip
                # anything that doesn't match (e.g. fragments of a truncated packet).
                if not isinstance(node, list) or len(node) < 4:
                    continue
                if not all(isinstance(f, str) for f in node[:4]):
                    continue
                ip, udp, tcp, node_id = cast("list[str]", node)[:4]
                neighbours.append(
                    {
                        "host": f"{hex_to_ip(ip)}:{hex_to_port(udp)}",
                        "port": hex_to_port(tcp),
                        "hash": node_id,
                    }
                )
    return {"neighbours": neighbours, "expiration": expiration}
