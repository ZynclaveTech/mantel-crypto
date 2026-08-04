// Argon2id password derivation and BLAKE2b subkey derivation.
//
// Spec §5.1: parameters are stored server-side PER USER alongside the salt,
// so a device that enrolled at 64 MiB can still log in after the default is
// raised. That is why all three tiers are vectors, not just the default.

/** Spec §5.1 fallback ladder. The client steps down only on allocation failure. */
export const ARGON2ID_TIERS = [
  { name: "default", memlimit: 256 * 1024 * 1024, opslimit: 4 },
  { name: "mid",     memlimit: 128 * 1024 * 1024, opslimit: 6 },
  { name: "low",     memlimit:  64 * 1024 * 1024, opslimit: 8 },
];

/** crypto_kdf contexts are EXACTLY 8 bytes. Both are wire spec - never change. */
export const AUTH_CONTEXT    = "mantelAu";
export const VARIANT_CONTEXT = "mantelFV";

/** Spec §5.2 step 4: KEK = Argon2id(password, salt, params). */
export function deriveKEK(sodium, password, salt, memlimit, opslimit) {
  return sodium.crypto_pwhash(
    32, password, salt, opslimit, memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

/**
 * Spec §5.2 step 5: loginKey = crypto_kdf_derive_from_key(KEK, 1, "mantelAu").
 * Base64 of this is sent to Cognito as the password, so the server never sees
 * the real one.
 */
export function deriveLoginKey(sodium, kek) {
  return sodium.crypto_kdf_derive_from_key(32, 1, AUTH_CONTEXT, kek);
}

/** Spec §7.2: per-variant subkeys, id 1=thumb, 2=preview, 3=original. */
export function deriveSubkey(sodium, key, id, context) {
  return sodium.crypto_kdf_derive_from_key(32, id, context, key);
}
