// XSalsa20-Poly1305 symmetric wrap (crypto_secretbox).
//
// One primitive, five uses in the spec §4 hierarchy:
//   master key   under KEK            (encMasterKey)
//   master key   under recovery key   (encMasterKeyByRecovery)
//   identity priv under master key    (encIdentityPriv)
//   collection key under master key   (owner's copy)
//   file key     under collection key (encFileKey)
// Metadata blobs (§7.4) use the same primitive with the file key.

export const NONCE_BYTES = 24;

export function sealKey(sodium, plaintextKey, nonce, wrappingKey) {
  if (nonce.length !== NONCE_BYTES) throw new Error(`nonce must be ${NONCE_BYTES} bytes`);
  return sodium.crypto_secretbox_easy(plaintextKey, nonce, wrappingKey);
}

export function openKey(sodium, ciphertext, nonce, wrappingKey) {
  if (nonce.length !== NONCE_BYTES) throw new Error(`nonce must be ${NONCE_BYTES} bytes`);
  // libsodium-wrappers throws on MAC failure, which is the behaviour we want:
  // an unauthenticated wrap is exactly the v1 flaw this protocol replaces.
  return sodium.crypto_secretbox_open_easy(ciphertext, nonce, wrappingKey);
}
