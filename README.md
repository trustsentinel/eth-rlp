# eth-rlp

RLP encoder/decoder for Ethereum node-discovery (discv4) UDP packets.

[![CI](https://github.com/trustsentinel/eth-rlp/actions/workflows/ci.yml/badge.svg)](https://github.com/trustsentinel/eth-rlp/actions/workflows/ci.yml)
`Status: Utility` · `Python 3.9+` · part of [TrustSentinel](https://trustsentinel.eu)

## Overview
A small, dependency-free RLP (Recursive Length Prefix) codec for the packets
exchanged during Ethereum's discv4 node-discovery handshake — the kind of
primitive the scanners are built on. It provides a strict, round-trippable
byte-level codec plus lenient hex helpers for real (often truncated) captures.

## Install
```bash
pip install ethrlp            # once published
pip install -e ".[dev]"       # from a clone, with test/lint tooling
```

## Usage
```python
import ethrlp

# Canonical RLP over bytes / nested lists (strict, round-trippable)
ethrlp.encode([b"cat", b"dog"]).hex()      # 'c88363617483646f67'
ethrlp.decode(bytes.fromhex("83646f67"))   # b'dog'

# Decode a discv4 NEIGHBOURS payload (hex) into a friendly dict
ethrlp.decode_neighbours_payload(hex_payload)
# {'neighbours': [{'host': '34.232.20.118:30311', 'port': 30311, 'hash': '...'}],
#  'expiration': '2023-11-14 22:13:20 UTC'}
```
See [`sample.py`](sample.py) for a full build-encode-decode round-trip:
```bash
python sample.py
```

## API
| Function | Purpose |
|---|---|
| `encode(item)` / `decode(data)` | strict canonical RLP over `bytes` / nested lists |
| `decode_hex(hex)` | lenient decode of a hex payload into a hex-string tree |
| `decode_neighbours_payload(hex)` | discv4 NEIGHBOURS → `{neighbours, expiration}` |
| `hex_to_ip`, `hex_to_port`, `decode_expiration` | discv4 field helpers |

The canonical `encode`/`decode` are strict (they reject trailing or truncated
input); the `decode_hex`/`decode_neighbours_payload` helpers are deliberately
lenient so partial UDP captures still yield what they can.

## Development
```bash
pip install -e ".[dev]"
ruff check .      # lint
mypy              # type-check
pytest            # tests
```

## Publishing
Tagging `vX.Y.Z` triggers [`release.yml`](.github/workflows/release.yml), which
builds and publishes to PyPI via **Trusted Publishing** (OIDC — no token in the
repo). One-time setup: add a trusted publisher on PyPI for this repo, workflow
`release.yml`, environment `pypi`.

## Layout
```
src/ethrlp/     # the package (rlp.py: codec + discv4 helpers)
tests/          # pytest suite
sample.py       # runnable example
```

## TrustSentinel
Part of [TrustSentinel](https://trustsentinel.eu) — secure connectivity and
network-intelligence tooling by Álvaro López.

- **[netso](https://github.com/trustsentinel/netso)** — secure-networking platform (SSI + end-to-end encryption)
- **[stk](https://github.com/trustsentinel/stk)** — browser-based remote shell broker
- **[stuk](https://github.com/trustsentinel/stuk)** — SSH access gating (port-knock + MFA)
- **[argos](https://github.com/trustsentinel/argos)** — P2P blockchain network scanning
- **[eth-rlp](https://github.com/trustsentinel/eth-rlp)** — RLP codec for Ethereum discv4  ·  _this repo_

## License
MIT
