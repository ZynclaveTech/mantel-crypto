// X25519 + XSalsa20-Poly1305 AUTHENTICATED sharing (crypto_box).
//
// Spec §6.1 is emphatic that crypto_box_seal (anonymous) must NOT be used.
// An anonymous envelope reproduces the exact v1 defect: a key delivery whose
// sender cannot be verified, which let any family member overwrite anyone's
// content key. With crypto_box, open() succeeds ONLY if the envelope was
// produced by the claimed sender's identity key.

/** Deterministic X25519 keypair from a 32-byte seed. */
export function identityKeypair(sodium, seed) {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  return sodium.crypto_box_seed_keypair(seed);
}

/** Spec §6.1 step 3: encCollectionKey = crypto_box(collectionKey, nonce, recipientPub, senderPriv). */
export function shareKey(sodium, key, nonce, recipientPub, senderPriv) {
  return sodium.crypto_box_easy(key, nonce, recipientPub, senderPriv);
}

/** Throws unless the envelope really came from senderPub. That is the point. */
export function openSharedKey(sodium, ciphertext, nonce, senderPub, recipientPriv) {
  return sodium.crypto_box_open_easy(ciphertext, nonce, senderPub, recipientPriv);
}
