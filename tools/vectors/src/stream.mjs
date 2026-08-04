// STREAM (Rogaway et al.) over XChaCha20-Poly1305. Spec §7.1.
//
// This is the design's ONE deliberate deviation from Ente's construction.
// libsodium's crypto_secretstream chains state between chunks, making
// decryption strictly sequential - fine for photos, fatal for video, because
// seeking to 40 minutes would mean decrypting the preceding 40 minutes.
// STREAM derives each chunk's nonce independently, so any chunk decrypts
// alone, while the counter and final-flag still give reordering and
// truncation detection.

export const CHUNK_SIZE = 8 * 1024 * 1024; // wire value; aligns with S3's 5 MiB min part size
export const NONCE_PREFIX_BYTES = 19;
export const TAG_BYTES = 16;

/** nonce = prefix(19) || counter(4, big-endian) || finalFlag(1). Total 24. */
export function buildNonce(noncePrefix, counter, isFinal) {
  if (noncePrefix.length !== NONCE_PREFIX_BYTES) {
    throw new Error(`noncePrefix must be ${NONCE_PREFIX_BYTES} bytes`);
  }
  if (counter < 0 || counter > 0xffffffff) throw new Error("counter out of range");
  const n = new Uint8Array(24);
  n.set(noncePrefix, 0);
  n[19] = (counter >>> 24) & 0xff;
  n[20] = (counter >>> 16) & 0xff;
  n[21] = (counter >>> 8) & 0xff;
  n[22] = counter & 0xff;
  n[23] = isFinal ? 0x01 : 0x00;
  return n;
}

/**
 * aad = fileId(16) || variantId(1). Binds every chunk to its file AND variant,
 * so a chunk cannot be spliced in from another file or another variant.
 */
export function buildAAD(fileId, variantId) {
  if (fileId.length !== 16) throw new Error("fileId must be 16 bytes");
  const aad = new Uint8Array(17);
  aad.set(fileId, 0);
  aad[16] = variantId;
  return aad;
}

export function encryptStream(sodium, plaintext, key, noncePrefix, fileId, variantId, chunkSize = CHUNK_SIZE) {
  const aad = buildAAD(fileId, variantId);
  const chunks = [];
  // An empty plaintext still produces one final chunk, so decrypt has
  // something to authenticate rather than silently accepting nothing.
  const total = Math.max(1, Math.ceil(plaintext.length / chunkSize));
  for (let i = 0; i < total; i++) {
    const slice = plaintext.subarray(i * chunkSize, Math.min((i + 1) * chunkSize, plaintext.length));
    const isFinal = i === total - 1;
    chunks.push(sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      slice, aad, null, buildNonce(noncePrefix, i, isFinal), key,
    ));
  }
  return chunks;
}

export function decryptStream(sodium, chunks, key, noncePrefix, fileId, variantId) {
  // Encrypt always emits at least one chunk (Math.max(1, ...) above), even for
  // an empty plaintext. A zero-length chunk list is therefore never a valid
  // encryption of anything - it means every object was deleted - so it must
  // be rejected rather than silently decrypted to zero bytes.
  if (chunks.length === 0) throw new Error("decryptStream: chunks must not be empty");
  const aad = buildAAD(fileId, variantId);
  const out = [];
  for (let i = 0; i < chunks.length; i++) {
    const isFinal = i === chunks.length - 1;
    // Throws on any mismatch: wrong counter (reorder), wrong final flag
    // (truncation), wrong fileId or variantId (splice), tampered bytes.
    out.push(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, chunks[i], aad, buildNonce(noncePrefix, i, isFinal), key,
    ));
  }
  const len = out.reduce((n, c) => n + c.length, 0);
  const merged = new Uint8Array(len);
  let off = 0;
  for (const c of out) { merged.set(c, off); off += c.length; }
  return merged;
}
