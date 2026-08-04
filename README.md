# Mantel Protocol — cryptographic core

[![CI](https://github.com/ZynclaveTech/mantel-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/ZynclaveTech/mantel-crypto/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The encryption used by [Mantel](https://mantel.live), an end-to-end encrypted
family photo app. This repository contains the cryptography and nothing else: no
service, no account system, no networking.

It is public so that the claim "photos are encrypted on your device before they
are uploaded" can be checked rather than taken on trust.

## Why there are three implementations

The same protocol is implemented three times, independently:

| | |
|---|---|
| [`ios/MantelCrypto`](ios/MantelCrypto) | Swift, over [swift-sodium](https://github.com/jedisct1/swift-sodium) |
| [`android/crypto`](android/crypto) | Kotlin, over [lazysodium](https://github.com/terl/lazysodium-java) |
| [`tools/vectors`](tools/vectors) | JavaScript, over [libsodium-wrappers-sumo](https://github.com/jedisct1/libsodium.js) — the reference oracle |

All three are pinned to one shared fixture, [`tools/vectors/vectors.json`](tools/vectors/vectors.json),
and each test suite locates and verifies itself against it. An implementation
that drifts fails its own tests.

That fixture is treated as read-only. Regenerating it is deliberately gated
behind an environment variable, because a vector file that can be regenerated to
match the code proves nothing — the point is that the code must match the
vectors, not the reverse.

## No novel cryptography

Every primitive is a standard libsodium construction:

- **Argon2id** for password-based key derivation
- **XChaCha20-Poly1305** for content encryption
- **crypto_kdf** (BLAKE2b) for deriving per-variant keys from a collection key
- **crypto_secretbox** and **crypto_box** for key wrapping
- **SHA-512** for safety numbers

There is no hand-rolled cipher, mode, or construction here. The security of the
system rests on correct use of reviewed primitives and on protocol design, not
on anything secret about the algorithms.

One deliberate omission worth naming: `crypto_box_seal` is not used anywhere.
Anonymous sealing hides the sender, and every place this protocol wraps a key
for another member is a place where the sender must be authenticated.

## Running the tests

```bash
# Swift
cd ios/MantelCrypto && swift test

# Kotlin (JVM, no emulator needed)
./gradlew :crypto:test

# JavaScript reference oracle
cd tools/vectors && npm ci && npm test
```

The Kotlin module is a plain JVM module, not an Android library — the crypto
core has no Android dependencies, so its tests run on a host JVM in
milliseconds. `LazySodium` is injected by the caller, which is what lets the
same classes run under `LazySodiumJava` in tests and `LazySodiumAndroid` in the
app.

## Directory layout

The layout mirrors the app repository this was extracted from. That is
intentional: both test suites find `tools/vectors/vectors.json` by walking up
from their own location, so preserving the paths means the vector tests run here
unchanged rather than depending on edits made during extraction.

## What is not here

The hosted service, its infrastructure, and the client applications are not part
of this repository. Publishing the cryptography is what makes the encryption
claim checkable; publishing the operational side would not add to that.

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Licence

Apache License 2.0 — see [LICENSE](LICENSE).
