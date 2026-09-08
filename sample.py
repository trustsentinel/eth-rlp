"""Build a discv4 NEIGHBOURS payload, RLP-encode it, then decode it back.

Run with the package installed (``pip install -e .``):  python sample.py
"""

import ethrlp


def node(ip: str, udp: int, tcp: int, node_id: bytes) -> list[bytes]:
    return [
        bytes(int(o) for o in ip.split(".")),
        udp.to_bytes(2, "big"),
        tcp.to_bytes(2, "big"),
        node_id,
    ]


nodes = [
    node("34.232.20.118", 30311, 30311, bytes(range(64))),
    node("10.0.0.5", 30303, 30303, bytes(range(64, 128))),
]
payload = ethrlp.encode([nodes, (1_700_000_000).to_bytes(4, "big")])

print("encoded (hex):", payload.hex()[:72], "...")
print("decoded:", ethrlp.decode_neighbours_payload(payload.hex()))
