# Design decisions

Choices that look arbitrary from the code but are load-bearing. Recorded so a
future change has to argue with the reason rather than rediscover it.

## Three implementations, one fixture

Swift, Kotlin and a JavaScript oracle implement the same protocol independently
and are all checked against `tools/vectors/vectors.json`.

The alternative — one implementation and two bindings to it — would be less
work and would catch nothing. Independent implementations disagree when a spec
is ambiguous, which is exactly when a protocol is most likely to be wrong.

**Direction matters:** implementations are measured against the vectors, never
the reverse. A fixture regenerated whenever a test fails records what the code
does instead of what the protocol requires. Regeneration is gated behind an
environment variable for that reason, and CI flags any pull request that changes
the file.

An earlier iteration generated vectors *from* the iOS test suite, which made iOS
the definition of correctness rather than a participant in it. The JavaScript
oracle exists to remove that privilege.

## No vector input may be random

Every constant in `tools/vectors/src/constants.mjs` is fixed. Nothing in that
package may call an RNG.

The consequence is the point: regenerate the vectors, and any diff means the
**wire format** changed. If inputs were random, every regeneration would produce
a diff and the signal would be worthless.

## `crypto_box_seal` is not used

Anonymous sealing is convenient — the sender needs no keypair. It is also wrong
here. Every place this protocol wraps a key for another member is a place where
the recipient must know who wrapped it. With sealing, anyone able to write to the
key-distribution path could insert a key that appears to come from a family
member, and the recipient could not tell.

The vectors include a non-member, Mallory, whose forged share must be rejected.

## Argon2id parameters are an allowlist, not a range

Approved pairs only: (256 MiB, 4), (128 MiB, 6), (64 MiB, 8).

The default tier has the **lowest** opslimit and the **highest** memlimit — so
"more of one, less of the other" is not a safe generalisation across tiers, and
an arbitrary combination could be cheap in both dimensions. A caller able to
choose freely — or a server able to influence the choice — could leave a stored
value one inexpensive inversion away from the password. Exact-pair matching is
the guard.

Stepping down happens only on allocation failure, not preference.

## The authentication value is a subkey, not the KEK

`authKey = kdf(KEK, index 1, "mantelAu")`.

The server receives something derived from the KEK rather than the KEK itself,
so a leak of what the server stores does not yield the value that unwraps the
master key.

## `KeyBox.seal` rejects empty plaintext

`open` rejects a tag-only ciphertext, so `seal` must refuse to produce one. The
alternative is a `seal` that succeeds and writes a ciphertext which will never
open again — undecryptable at rest, discovered only when someone reads it back.
No key this class wraps is legitimately empty, so the restriction costs nothing.

This symmetry is deliberately tighter than `ContentStream.open`, which accepts
`>= tagBytes` because an empty *file* is legitimate.

## Per-variant subkeys, not the file key

The three renditions of a photo share a file key. Encrypting them all under it
would reuse keystream across related plaintexts. Each variant gets
`kdf(fileKey, index = variantId, "mantelFV")` and its own fresh 19-byte nonce
prefix.

The variant id is also in the AAD, so a chunk cannot be moved between variants
even though they descend from one key.

## Nonce carries a final-chunk flag

`prefix(19) || counter(4) || finalFlag(1)`.

Without the flag, an attacker could truncate the chunk sequence and the
remainder would still authenticate — a shorter, valid-looking file. The flag
means only the genuine last chunk carries it.

## Safety numbers are 5200 iterations, not a short fingerprint

An earlier version displayed a 6-hex-character fingerprint — 24 bits. Grinding
an X25519 keypair to match a chosen 24-bit target is roughly 16 million
keygens: seconds on a laptop. The "compare this code with your family member"
step was defeatable by construction, which is worse than not offering it, since
users act on a check they believe works.

The current scheme is iterated SHA-512 with a cost chosen so that grinding a
colliding key is not cheap.

## The Kotlin module is plain JVM, not an Android library

The crypto core has no Android dependencies, so its tests run on a host JVM in
milliseconds with no emulator. `LazySodium` is injected by the caller:
`LazySodiumJava` in tests, `LazySodiumAndroid` in the app.

`lazysodium-java` is `compileOnly` because the app supplies
`lazysodium-android` at runtime, and having both on one classpath risks
duplicate classes — the Android AAR bundles the Java classes.

## Layout mirrors the app repository

`ios/`, `android/` and `tools/` sit at the root here exactly as they do in the
app repo this was extracted from. Both test suites locate the vector fixture by
walking *up* from their own location, so preserving the paths means the vector
tests run unchanged rather than depending on edits made during extraction.

A prettier `swift/` + `kotlin/` split would have required editing the lookups —
i.e. changing test code as part of publishing it, which is precisely when you
least want to.
