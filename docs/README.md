# Documentation

| | |
|---|---|
| [PROTOCOL.md](PROTOCOL.md) | Primitives, sizes, password derivation, subkey derivation, the key hierarchy, and key wrapping |
| [FILE-FORMAT.md](FILE-FORMAT.md) | Chunked content encryption: nonce construction, AAD, and what the format deliberately does not do |
| [THREAT-MODEL.md](THREAT-MODEL.md) | What the protocol defends against, and — more usefully — what it does not |
| [DESIGN-DECISIONS.md](DESIGN-DECISIONS.md) | Choices that look arbitrary in the code but are load-bearing |

Everything here is derived from the implementations in this repository and
pinned by [`tools/vectors/vectors.json`](../tools/vectors/vectors.json). Where a
document and the code disagree, **the code and the vectors are correct** and the
document is a bug worth reporting.

Start with [PROTOCOL.md](PROTOCOL.md) for what the protocol is, and
[THREAT-MODEL.md](THREAT-MODEL.md) for what it claims.
