# Threat model

Stated so it can be argued with. A threat model that only lists what a system
defends against is marketing; the limits below are the useful half.

## What is assumed

- **The server is not trusted with content.** It stores ciphertext, serves it
  back, and coordinates who may fetch what. It is assumed to be honest about
  availability and dishonest about everything else.
- **The transport is not trusted.** TLS is used, but no security property here
  depends on it.
- **The user's device is trusted while unlocked.** Keys exist in memory on an
  unlocked device; that is unavoidable for an app that displays photos.

## Defended

**A server operator, or anyone who obtains the stored data, cannot read
photos.** Content is encrypted on the device under keys the server never holds.
Compromising the storage yields ciphertext, per-file nonce prefixes, and sizes.

**The server cannot forge a key share from a family member.** Key sharing uses
`crypto_box`, which authenticates the sender. `crypto_box_seal` — which would
hide the sender — is deliberately unused, so a party who can write to the
key-distribution path cannot insert a key that appears to come from someone
else.

**Chunks cannot be reordered, substituted across variants, or truncated
silently.** The nonce binds each chunk to its index, the AAD binds it to
`fileId || variantId`, and the final-chunk flag means dropping trailing chunks
fails authentication rather than yielding a shorter valid file.

**A stolen authentication value does not unwrap anything.** What the client
sends to authenticate is a KDF subkey of the KEK (`mantelAu`, index 1), not the
KEK itself.

**Password guessing is expensive.** Argon2id at 256 MiB / 4 passes by default,
and the approved-parameter allowlist prevents a caller or a malicious server
from requesting cheap parameters. Mixing tiers is rejected.

**Losing the password does not lose the photos.** The master key is wrapped
twice — under the password-derived KEK and independently under a recovery key —
so recovery never requires the server to have held the master key.

## Not defended — and why

**A compromised device.** Malware with the app's privileges on an unlocked
device can read the master key from memory. No client-side encryption scheme
survives this.

**A malicious build of the client.** The security of "encrypted before upload"
depends on the binary actually being the code in this repository. Publishing the
source makes verification *possible*; it does not make it automatic. Reproducible
builds would close this and are not implemented.

**An attacker with the password and the recovery material.** By design, those
two are what reconstruct the master key.

**Metadata.** The server learns who uploads, when, how often, how large each
file is (to within a chunk), and who shares with whom. Content is hidden;
patterns are not. There is no padding and no cover traffic.

**Traffic analysis and timing.** Out of scope.

**Denial of service.** A hostile server can refuse to serve, or delete data. The
protocol protects confidentiality and integrity, not availability.

**Post-quantum adversaries.** X25519 and XSalsa20-Poly1305 are classical. An
adversary who stores ciphertext now and has a cryptographically relevant quantum
computer later can recover key-sharing material.

## Cryptographic assumptions inherited

The protocol is only as strong as libsodium's implementations of Argon2id,
BLAKE2b, XChaCha20-Poly1305, XSalsa20-Poly1305, X25519 and SHA-512, and as the
bindings used on each platform (swift-sodium, lazysodium,
libsodium-wrappers-sumo). A break in any of those is a break here.

## Reporting

If you can violate a "defended" claim above, that is a vulnerability — see
[SECURITY.md](../SECURITY.md). If you think a "not defended" item should be
defended, that is a design discussion and an issue is fine.
