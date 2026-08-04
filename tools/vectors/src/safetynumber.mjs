// 60-digit safety number. Spec §6.2.
//
// Modelled on Signal's safety-number scheme (iterated SHA-512 over
// version||pubkey||identifier, truncated to 30 bytes, rendered as six 5-digit
// decimal groups) so it can be reviewed against a known reference design.
// It has NOT been verified byte-for-byte against Signal's implementation
// (org.whispersystems.libsignal.fingerprint.NumericFingerprintGenerator /
// DisplayableFingerprint). Two known deltas, found by reading that source:
//   1. Signal's first iteration re-hashes (version||pubkey||id) with the
//      public key appended a second time (digest.digest(publicKey) after
//      digest.update(initialBytes)); this implementation's first iteration
//      hashes version||pubkey||id alone, without that extra append. The two
//      diverge from the very first round.
//   2. Signal breaks the tie between the two parties by comparing the
//      *rendered digit strings*; this implementation compares the raw public
//      keys instead. Both are valid symmetric orderings, but they are not the
//      same rule.
// The digit encoding itself (five bytes, big-endian, mod 100000, zero-padded
// to 5 digits, six such groups per party) does match Signal's
// DisplayableFingerprint.getEncodedChunk byte-for-byte.
//
// v1 showed a 6-hex-char fingerprint - 24 bits. Grinding an X25519 keypair to
// a chosen 24-bit fingerprint is ~16M keygens, i.e. seconds on a laptop, so
// the guardian's "verify this code" step was bypassable by construction.

const ITERATIONS = 5200;
const VERSION = 0;

/** Per-party: iterated SHA-512 over version||pubkey||identifier, first 30 bytes. */
function partyFingerprint(sodium, pubKey, identifier) {
  const id = Uint8Array.from(Buffer.from(identifier, "utf8"));
  const seed = new Uint8Array(2 + pubKey.length + id.length);
  seed[0] = (VERSION >> 8) & 0xff;
  seed[1] = VERSION & 0xff;
  seed.set(pubKey, 2);
  seed.set(id, 2 + pubKey.length);

  let h = sodium.crypto_hash_sha512(seed);
  // Signal re-hashes hash||pubkey each round; the pubkey re-injection is what
  // makes the iteration count meaningful rather than a plain hash chain.
  for (let i = 1; i < ITERATIONS; i++) {
    const buf = new Uint8Array(h.length + pubKey.length);
    buf.set(h, 0);
    buf.set(pubKey, h.length);
    h = sodium.crypto_hash_sha512(buf);
  }
  return h.slice(0, 30);
}

/** 30 bytes -> six 5-byte groups -> each big-endian uint40 mod 100000, 5 digits. */
function encodeDigits(fp) {
  let out = "";
  for (let i = 0; i < 30; i += 5) {
    let v = 0n;
    for (let j = 0; j < 5; j++) v = (v << 8n) | BigInt(fp[i + j]);
    out += String(v % 100000n).padStart(5, "0");
  }
  return out;
}

/**
 * One party's own 30-digit half, exposed so the fixture can pin each side
 * independently (spec §6.2) rather than only the concatenated 60-digit value.
 */
export function partyDigits(sodium, pubKey, identifier) {
  return encodeDigits(partyFingerprint(sodium, pubKey, identifier));
}

/**
 * Concatenate both parties' 30-digit strings in ascending order of their
 * public keys, so both sides compute the same 60 digits regardless of who
 * is "local".
 */
export function safetyNumber(sodium, pubA, subA, pubB, subB) {
  const a = { pub: pubA, digits: encodeDigits(partyFingerprint(sodium, pubA, subA)) };
  const b = { pub: pubB, digits: encodeDigits(partyFingerprint(sodium, pubB, subB)) };
  const cmp = Buffer.compare(Buffer.from(a.pub), Buffer.from(b.pub));
  return cmp <= 0 ? a.digits + b.digits : b.digits + a.digits;
}
