# File format — chunked content encryption

Photos are encrypted as a sequence of independently-sealed chunks rather than
one large ciphertext, so a client can decrypt and display progressively and
resume a partial transfer without holding the whole file in memory.

## Chunking

Plaintext is split into **8 MiB** chunks. A zero-length input still produces one
chunk, so every file has at least one.

Each chunk is sealed with XChaCha20-Poly1305 (IETF) and carries its own 16-byte
Poly1305 tag. Ciphertext chunk size is therefore plaintext + 16.

## Nonce construction

libsodium's `aead.xchacha20poly1305ietf.encrypt` generates its own nonce and
offers no explicit-nonce overload, so this protocol builds the nonce itself in
the STREAM style:

```
nonce (24 bytes) = prefix (19) || counter (4, big-endian) || finalFlag (1)
```

- **prefix** — 19 bytes, freshly random per `(file, variant)`. Never reused.
- **counter** — chunk index, big-endian.
- **finalFlag** — `1` on the last chunk, `0` otherwise.

The final flag is what makes **truncation** detectable. An attacker who drops
trailing chunks cannot make the remaining stream look complete, because the last
chunk a legitimate encryptor produced is the only one sealed with the flag set.

## Additional authenticated data

```
aad = fileId (16) || variantId (1)
```

`fileId` is the photo's UUID as **raw 16 bytes**, not its string form.

This binds every chunk to both its file and its variant. Without the variant in
the AAD, a thumbnail chunk could be substituted for the corresponding chunk of
the preview or original.

## Keys

A chunk is **never** encrypted under the raw file key. The key is always the
per-variant subkey:

```
variantKey = crypto_kdf(fileKey, index = variantId, context = "mantelFV")
```

Distinct per-variant subkeys are what prevent keystream reuse across the three
renditions of the same photo, which share a file key.

Each variant also gets its own fresh 19-byte nonce prefix. Storage keeps
`noncePrefix{thumb,preview,original}` per photo.

## Decryption

Decryption mirrors encryption exactly: same nonce for the same index, same AAD,
same variant key. A chunk that fails authentication is an error — there is no
partial-accept path.

## What this format does not do

- **No header.** There is no magic number or version field in the ciphertext
  itself; the variant and file identity live in the AAD, and the layout is
  determined by the protocol version the storage layer records.
- **No padding.** Ciphertext length reveals plaintext length to within a chunk.
  A file's approximate size is not hidden from the server.
- **No per-chunk ordering proof beyond the counter.** Chunks are bound to their
  index by the nonce, so reordering fails authentication, but the count of
  chunks is not separately authenticated — the final flag is what closes the
  stream.
