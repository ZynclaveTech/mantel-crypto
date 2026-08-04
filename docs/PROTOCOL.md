# Mantel Protocol v2 — specification

Every constant and construction below is taken from the implementations in this
repository and pinned by [`tools/vectors/vectors.json`](../tools/vectors/vectors.json).
Where this document and the code disagree, the code and the vectors are correct
and this document is a bug — please report it.

## Primitives

| Purpose | Construction | libsodium |
|---|---|---|
| Password → key | Argon2id | `crypto_pwhash` |
| Subkey derivation | BLAKE2b | `crypto_kdf_derive_from_key` |
| Content encryption | XChaCha20-Poly1305 (IETF) | `crypto_aead_xchacha20poly1305_ietf` |
| Symmetric key wrapping | XSalsa20-Poly1305 | `crypto_secretbox` |
| Authenticated key sharing | X25519 + XSalsa20-Poly1305 | `crypto_box` |
| Safety numbers | SHA-512 | `crypto_hash_sha512` |

Nothing is hand-rolled. There is no custom cipher, mode, padding scheme, or
KDF.

## Sizes

| | bytes |
|---|---|
| Symmetric key | 32 |
| AEAD nonce | 24 (19-byte prefix + 4-byte counter + 1-byte final flag) |
| `secretbox` nonce | 24 |
| Poly1305 tag | 16 |
| Chunk (plaintext) | 8 MiB |
| KDF context | exactly 8 |

## Password derivation

```
KEK = Argon2id(password, salt, memlimit, opslimit)
```

`memlimit`/`opslimit` are **not caller-chosen**. They must match one of three
approved tiers exactly, as an (memlimit, opslimit) pair:

| tier | memlimit | opslimit |
|---|---|---|
| `default` | 256 MiB | 4 |
| `mid` | 128 MiB | 6 |
| `low` | 64 MiB | 8 |

The client steps down only on allocation failure — a device that cannot
allocate 256 MiB.

**The allowlist is load-bearing, not defensive decoration.** It is an exact-pair
match precisely because the default tier has the *lowest* opslimit and the
*highest* memlimit. Allowing an arbitrary combination would let a caller (or a
compromised server choosing parameters) request something cheap in both
dimensions, leaving a stored value one inexpensive Argon2id inversion away from
the password. Mixing the memlimit of one tier with the opslimit of another is
rejected.

## Subkey derivation

```
subkey = crypto_kdf_derive_from_key(key, index, context)
```

`context` is exactly 8 bytes. Two contexts exist:

| context | purpose |
|---|---|
| `mantelAu` | login key, `index = 1`, derived from the KEK |
| `mantelFV` | per-variant file keys, `index = variantId`, derived from the file key |

Deriving the login key as a subkey of the KEK means the value sent to the server
for authentication is *not* the key that unwraps anything.

## Key hierarchy

Each `secretbox` below is a `KeyBox` wrap; the fixture section that pins it is
named in brackets.

```
password ──Argon2id(salt, tier)──> KEK
                                    ├──kdf(index=1, "mantelAu")──> login key → server
                                    └──secretbox──> master key   [master_key_by_kek]

recovery key ──secretbox──> master key                           [master_key_by_recovery]

master key ──secretbox──> identity private key (X25519)          [identity_priv_by_master]
           └─secretbox──> collection key                         [collection_key_by_master]

collection key ──secretbox──> file key                           [file_key_by_collection]

file key ──secretbox──> metadata                                 [metadata_by_file_key]
         └─kdf(index=variantId, "mantelFV")──> variant key ──> content chunks
```

Two independent wraps of the master key — one under the KEK, one under the
recovery key — are what make password recovery possible without the server ever
holding the master key.

Note that metadata is encrypted under the **file key** itself, while content is
encrypted under a **per-variant subkey** of it.

**Variant keys must come from `deriveVariantKey`.** Deriving them any other way,
even equivalently, breaks the property that one file key yields exactly one set
of variant keys.

## Variant identifiers

Wire values. Changing these breaks every existing file.

| variant | id |
|---|---|
| thumbnail | 1 |
| preview | 2 |
| original | 3 |

## Key wrapping — `KeyBox`

`crypto_secretbox` over a 24-byte nonce.

`seal` **rejects an empty plaintext**, and `open` rejects a tag-only
ciphertext. The two are deliberately symmetric: without the check on `seal`, it
would be possible to persist a ciphertext that `open` will refuse forever —
undecryptable at rest, discovered only when someone tries to read it back. No
key this class wraps is ever legitimately empty.

## Authenticated sharing — `IdentityBox`

`crypto_box` (X25519 + XSalsa20-Poly1305), which authenticates the sender.

**`crypto_box_seal` is deliberately not used anywhere in this protocol.**
Anonymous sealing hides the sender. Every place this protocol wraps a key for
another member is a place where the recipient must be able to tell *who* wrapped
it — otherwise anyone able to write to the key-distribution path could insert
keys that appear to come from a family member. The test vectors include a
non-member ("Mallory") whose forged share must be rejected.

## Safety numbers

A safety number lets two members compare identity keys out of band. The
construction is iterated SHA-512, in the style of Signal's:

```
h1 = SHA512(version(2, big-endian) || pubkey || utf8(identifier))
hi = SHA512(h(i-1) || pubkey)          for i = 2 … 5200
```

The iteration count is deliberate cost: it makes generating a key whose safety
number collides with a target's meaningfully expensive.

**Two documented deltas from Signal's scheme.** The digit encoding is identical;
these are not:

1. Signal re-appends the public key an extra time on its first hash iteration.
2. Signal orders the two parties unconditionally by rendered digit string. Mantel
   orders by raw public-key bytes, falling back to digit strings only when the
   two keys are byte-identical.

The vectors pin Mantel's exact form, so an implementation that follows Signal's
variant will fail them. Stated precisely here because the threat model is
published and a safety number that differs between platforms is worthless.

## Content encryption

See [FILE-FORMAT.md](FILE-FORMAT.md).

## Test vectors

[`tools/vectors/vectors.json`](../tools/vectors/vectors.json) is generated by a
JavaScript reference implementation and consumed by the Swift and Kotlin test
suites. Every input is a fixed constant — no vector input comes from a random
number generator — so regenerating the file and finding a diff means the **wire
format changed**, not that entropy moved.

The fixture is read-only by policy. See [CONTRIBUTING.md](../CONTRIBUTING.md).
