// Every input to the vector generator is fixed here. Nothing in this package
// may call a random-number generator: the vectors must be reproducible, so
// that regenerating them and finding a diff means the WIRE FORMAT changed,
// not that entropy moved. See the CI guard in the final task.

/** Decode a hex string to bytes. */
export const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));

// --- Symmetric key material (32 bytes each) ---
export const MASTER_KEY     = hex("0101010101010101010101010101010101010101010101010101010101010101");
export const RECOVERY_KEY   = hex("0202020202020202020202020202020202020202020202020202020202020202");
export const COLLECTION_KEY = hex("0303030303030303030303030303030303030303030303030303030303030303");
export const FILE_KEY       = hex("0404040404040404040404040404040404040404040404040404040404040404");

// --- Password derivation inputs ---
export const PASSWORD = "correct horse battery staple";
export const KDF_SALT = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"); // 16 bytes

// --- Identity keypair seeds. Alice and Bob are family members; Mallory is
//     the non-member whose forged share must be rejected (spec §11). ---
export const ALICE_SEED   = hex("1111111111111111111111111111111111111111111111111111111111111111");
export const BOB_SEED     = hex("2222222222222222222222222222222222222222222222222222222222222222");
export const MALLORY_SEED = hex("3333333333333333333333333333333333333333333333333333333333333333");

// Cognito subs are opaque strings; these are fixed UUIDs for reproducibility.
export const ALICE_SUB   = "11111111-1111-4111-8111-111111111111";
export const BOB_SUB     = "22222222-2222-4222-8222-222222222222";
export const MALLORY_SUB = "33333333-3333-4333-8333-333333333333";

// --- Content encryption inputs ---
export const FILE_ID = hex("deadbeefdeadbeefdeadbeefdeadbeef"); // 16-byte UUID
