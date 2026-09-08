import pytest

import ethrlp
from ethrlp import (
    decode,
    decode_expiration,
    decode_neighbours_payload,
    encode,
    hex_to_ip,
    hex_to_port,
)

# A real (partial) discv4 NEIGHBOURS capture — intentionally truncated, as UDP
# captures often are. Used to check the lenient decoder degrades gracefully.
TRUNCATED_NEIGHBOURS = (
    "f903bcf903b4f84d8422e81476827667827667b8405ce9805aeb64865688f0f097620de7416c14df97"
    "93f89ae9acfac6f9094881e81d00ac6a8c7bbe932edf756c8289801047647026e71c74b000d038a8f8"
    "54f05f84d84a1615be9826ff1826ff1b840ff2f412bdd492f8832378613353a023120d4cf524c0ffc1"
    "f0880a64b884fcff57a23c9c47206f0f28c848b7e35d71b2c10312664ebbbf7388df44a81da28e28"
)


class TestCanonicalRLP:
    @pytest.mark.parametrize(
        "item, expected_hex",
        [
            (b"", "80"),
            (b"\x00", "00"),
            (b"\x0f", "0f"),
            (b"\x7f", "7f"),
            (b"\x80", "8180"),
            (b"dog", "83646f67"),
            ([b"cat", b"dog"], "c88363617483646f67"),
            ([], "c0"),
            (b"\x00" * 56, "b838" + "00" * 56),  # long string boundary
        ],
    )
    def test_encode_vectors(self, item, expected_hex):
        assert encode(item).hex() == expected_hex

    @pytest.mark.parametrize(
        "item",
        [
            b"",
            b"\x00",
            b"hello world",
            b"x" * 1024,  # long string
            [b"a", [b"b", [b"c"]], b""],  # nesting
            [[b"1"] * 40],  # long list
        ],
    )
    def test_roundtrip(self, item):
        assert decode(encode(item)) == item

    def test_decode_rejects_trailing_bytes(self):
        with pytest.raises(ValueError):
            decode(encode(b"dog") + b"\xff")

    def test_decode_rejects_truncated(self):
        # A declared length longer than the input must be rejected (strict).
        with pytest.raises(ValueError):
            decode(bytes.fromhex(TRUNCATED_NEIGHBOURS))

    def test_encode_rejects_bad_type(self):
        with pytest.raises(TypeError):
            encode(42)  # type: ignore[arg-type]


def _make_neighbours_payload():
    def node(ip, udp, tcp, node_id):
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
    expiration = (1_700_000_000).to_bytes(4, "big")
    return encode([nodes, expiration])


class TestNeighbours:
    def test_roundtrip_complete_payload(self):
        raw = _make_neighbours_payload()
        result = decode_neighbours_payload(raw.hex())
        assert result["expiration"] == "2023-11-14 22:13:20 UTC"
        assert [n["host"] for n in result["neighbours"]] == [
            "34.232.20.118:30311",
            "10.0.0.5:30303",
        ]
        assert result["neighbours"][0]["port"] == 30311
        assert result["neighbours"][0]["hash"] == bytes(range(64)).hex()

    def test_handles_truncated_capture(self):
        # Lenient: no exception, and the first (complete) neighbour is recovered.
        result = decode_neighbours_payload(TRUNCATED_NEIGHBOURS)
        assert result["neighbours"][0]["host"] == "34.232.20.118:30311"


class TestHelpers:
    def test_hex_to_ip(self):
        assert hex_to_ip("22e81476") == "34.232.20.118"

    def test_hex_to_port(self):
        assert hex_to_port("7667") == 30311
        assert hex_to_port("") == 0

    def test_decode_expiration(self):
        assert decode_expiration(format(1_700_000_000, "x")) == "2023-11-14 22:13:20 UTC"


def test_version():
    assert isinstance(ethrlp.__version__, str)
