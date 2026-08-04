// Assembles vectors.json from the reference implementation.
//
// This file is the ONLY one in the package that does I/O. Everything in src/
// is pure. Run with: npm run generate
//
// Output MUST be byte-reproducible. Nothing here may call an RNG - every
// input comes from src/constants.mjs. That is what makes the CI drift check
// in vectors-ci.yml meaningful: a diff means the wire format changed.

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadSodium } from "./src/sodium.mjs";

import * as C from "./src/constants.mjs";
import { ARGON2ID_TIERS, deriveKEK, deriveLoginKey, deriveSubkey, AUTH_CONTEXT, VARIANT_CONTEXT } from "./src/kdf.mjs";
import { sealKey } from "./src/keybox.mjs";
import { identityKeypair, shareKey } from "./src/identitybox.mjs";
import { encryptStream, buildNonce, buildAAD, CHUNK_SIZE, NONCE_PREFIX_BYTES } from "./src/stream.mjs";
import { safetyNumber, partyDigits } from "./src/safetynumber.mjs";

const hexOf = (b) => Buffer.from(b).toString("hex");

// Fixed nonces - see the no-RNG rule above.
const NONCE_MASTER_BY_KEK      = C.hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
const NONCE_MASTER_BY_RECOVERY = C.hex("b1b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
const NONCE_IDENTITY_PRIV      = C.hex("b2b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
const NONCE_COLLECTION_KEY     = C.hex("b3b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
const NONCE_FILE_KEY           = C.hex("b4b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
const NONCE_METADATA           = C.hex("b5b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7");
const NONCE_SHARE              = C.hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7");

// Spec §7.1: "noncePrefix (19 B, random per variant)". These three fixed
// constants model that per-variant randomness while keeping the fixture
// reproducible (see the no-RNG rule above) - one prefix per variant id,
// never shared across variants of the same file.
const STREAM_PREFIX_BY_VARIANT = {
  1: C.hex("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2"), // thumb
  2: C.hex("e1e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f3"), // preview
  3: C.hex("e2e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f4"), // original
};

// A second, fixed fileId - distinct from C.FILE_ID - used only to build the
// "spliced chunk from another file" negative vector below.
const OTHER_FILE_ID = C.hex("ffffffffffffffffffffffffffffffff");

// Small chunk size in the fixture so multi-chunk cases stay tiny. Clients MUST
// use CHUNK_SIZE (8 MiB) in production; the fixture states both so a client can
// assert it knows the real value.
const FIXTURE_CHUNK_SIZE = 64;

const METADATA_JSON = JSON.stringify({
  filename: "IMG_0042.HEIC",
  width: 4032,
  height: 3024,
  capturedAt: "2024-06-12T14:30:00Z",
});

async function main() {
  const sodium = await loadSodium();

  const alice = identityKeypair(sodium, C.ALICE_SEED);
  const bob = identityKeypair(sodium, C.BOB_SEED);
  const mallory = identityKeypair(sodium, C.MALLORY_SEED);

  // --- KDF: all three tiers, because params are stored per user (spec §5.1) ---
  const kdf = ARGON2ID_TIERS.map((t) => {
    const kek = deriveKEK(sodium, C.PASSWORD, C.KDF_SALT, t.memlimit, t.opslimit);
    return {
      tier: t.name,
      password: C.PASSWORD,
      salt_hex: hexOf(C.KDF_SALT),
      memlimit: t.memlimit,
      opslimit: t.opslimit,
      alg: "argon2id13",
      kek_hex: hexOf(kek),
      login_key_hex: hexOf(deriveLoginKey(sodium, kek)),
      login_key_b64: Buffer.from(deriveLoginKey(sodium, kek)).toString("base64"),
    };
  });

  const subkeys = {
    context: VARIANT_CONTEXT,
    auth_context: AUTH_CONTEXT,
    file_key_hex: hexOf(C.FILE_KEY),
    variants: [
      { id: 1, name: "thumb",    subkey_hex: hexOf(deriveSubkey(sodium, C.FILE_KEY, 1, VARIANT_CONTEXT)) },
      { id: 2, name: "preview",  subkey_hex: hexOf(deriveSubkey(sodium, C.FILE_KEY, 2, VARIANT_CONTEXT)) },
      { id: 3, name: "original", subkey_hex: hexOf(deriveSubkey(sodium, C.FILE_KEY, 3, VARIANT_CONTEXT)) },
    ],
  };

  // --- KeyBox: all five wrap sites from the §4 hierarchy, plus metadata ---
  const wrap = (pt, nonce, key) => ({
    plaintext_hex: hexOf(pt),
    nonce_hex: hexOf(nonce),
    wrapping_key_hex: hexOf(key),
    ciphertext_hex: hexOf(sealKey(sodium, pt, nonce, key)),
  });

  const kekLow = deriveKEK(sodium, C.PASSWORD, C.KDF_SALT, ARGON2ID_TIERS[2].memlimit, ARGON2ID_TIERS[2].opslimit);
  const keybox = {
    master_key_by_kek:      { ...wrap(C.MASTER_KEY, NONCE_MASTER_BY_KEK, kekLow), note: "KEK from the 'low' tier" },
    master_key_by_recovery: wrap(C.MASTER_KEY, NONCE_MASTER_BY_RECOVERY, C.RECOVERY_KEY),
    identity_priv_by_master: wrap(alice.privateKey, NONCE_IDENTITY_PRIV, C.MASTER_KEY),
    collection_key_by_master: wrap(C.COLLECTION_KEY, NONCE_COLLECTION_KEY, C.MASTER_KEY),
    file_key_by_collection: wrap(C.FILE_KEY, NONCE_FILE_KEY, C.COLLECTION_KEY),
    metadata_by_file_key: {
      plaintext_utf8: METADATA_JSON,
      nonce_hex: hexOf(NONCE_METADATA),
      wrapping_key_hex: hexOf(C.FILE_KEY),
      ciphertext_hex: hexOf(sealKey(sodium, Uint8Array.from(Buffer.from(METADATA_JSON, "utf8")), NONCE_METADATA, C.FILE_KEY)),
    },
  };

  // --- IdentityBox: a real share, and a forged one that MUST fail to open ---
  const identity = {
    alice: { seed_hex: hexOf(C.ALICE_SEED), pub_hex: hexOf(alice.publicKey), priv_hex: hexOf(alice.privateKey), sub: C.ALICE_SUB },
    bob:   { seed_hex: hexOf(C.BOB_SEED),   pub_hex: hexOf(bob.publicKey),   priv_hex: hexOf(bob.privateKey),   sub: C.BOB_SUB },
    mallory: { seed_hex: hexOf(C.MALLORY_SEED), pub_hex: hexOf(mallory.publicKey), priv_hex: hexOf(mallory.privateKey), sub: C.MALLORY_SUB },
    share_alice_to_bob: {
      plaintext_hex: hexOf(C.COLLECTION_KEY),
      nonce_hex: hexOf(NONCE_SHARE),
      ciphertext_hex: hexOf(shareKey(sodium, C.COLLECTION_KEY, NONCE_SHARE, bob.publicKey, alice.privateKey)),
    },
    forged_by_mallory_claiming_alice: {
      nonce_hex: hexOf(NONCE_SHARE),
      ciphertext_hex: hexOf(shareKey(sodium, C.COLLECTION_KEY, NONCE_SHARE, bob.publicKey, mallory.privateKey)),
      must_fail_to_open_as: "alice",
      note: "In v1 this would have been accepted. Opening with alice's pubkey MUST throw.",
    },
  };

  // --- Stream: single, multi, exact-boundary, and short-final cases ---
  //
  // CRITICAL FIX: each case now derives its OWN content key via
  // deriveSubkey(FILE_KEY, variantId, VARIANT_CONTEXT) and uses its OWN
  // per-variant nonce prefix. Previously every case - including different
  // variants of the same file - was encrypted under the raw C.FILE_KEY with
  // the single shared STREAM_PREFIX, which is a two-time pad across variants
  // (spec §7.1/§7.2 both require this NOT to happen).
  const body = (n) => Uint8Array.from({ length: n }, (_, i) => i % 251);
  const streamCase = (name, len, variantId) => {
    const pt = body(len);
    const key = deriveSubkey(sodium, C.FILE_KEY, variantId, VARIANT_CONTEXT);
    const noncePrefix = STREAM_PREFIX_BY_VARIANT[variantId];
    const chunks = encryptStream(sodium, pt, key, noncePrefix, C.FILE_ID, variantId, FIXTURE_CHUNK_SIZE);
    return {
      name,
      variant_id: variantId,
      key_hex: hexOf(key),
      nonce_prefix_hex: hexOf(noncePrefix),
      plaintext_hex: hexOf(pt),
      plaintext_len: len,
      chunk_size: FIXTURE_CHUNK_SIZE,
      chunks_hex: chunks.map(hexOf),
      nonces_hex: chunks.map((_, i) => hexOf(buildNonce(noncePrefix, i, i === chunks.length - 1))),
      aad_hex: hexOf(buildAAD(C.FILE_ID, variantId)),
    };
  };

  const streamCases = [
    streamCase("single_short_chunk", 10, 1),
    streamCase("exact_chunk_boundary", FIXTURE_CHUNK_SIZE * 2, 1),
    streamCase("multi_chunk_short_final", FIXTURE_CHUNK_SIZE * 3 + 7, 1),
    streamCase("other_variant_same_file", FIXTURE_CHUNK_SIZE * 2, 2),
    streamCase("empty_plaintext", 0, 1),
    // Variant 3 ("original") carries the full-resolution photo/video - the
    // largest objects and the ones that realistically span many chunks in
    // production - yet had no stream case at all until now. Multi-chunk with
    // a short final chunk, same shape as multi_chunk_short_final, so the
    // reference byte-for-byte pinning and the two-time-pad guard both cover
    // variant 3, not just variants 1 and 2.
    streamCase("original_variant_multi_chunk_short_final", FIXTURE_CHUNK_SIZE * 4 + 23, 3),
  ];

  // Composition assertion (finding: CRITICAL, item 5): the content key each
  // stream case actually used MUST equal the subkey the subkeys section
  // separately publishes for that variant. This is the check that would have
  // caught the original bug - two independently-correct modules (kdf.mjs's
  // subkey derivation and stream.mjs's encryption) composed incorrectly
  // because generate.mjs never wired one into the other.
  for (const c of streamCases) {
    // Lookup by id, not by array index: subkeys.variants[c.variant_id - 1]
    // silently compares against the wrong variant if that array is ever
    // reordered or filtered. This is THE assertion that exists to catch
    // composition bugs, so it must not itself be fragile to reordering.
    const variant = subkeys.variants.find((v) => v.id === c.variant_id);
    if (!variant) {
      throw new Error(
        `composition check failed: stream case "${c.name}" claims variant_id=${c.variant_id}, ` +
        `which has no entry in subkeys.variants`,
      );
    }
    const expected = variant.subkey_hex;
    if (c.key_hex !== expected) {
      throw new Error(
        `composition check failed: stream case "${c.name}" (variant_id=${c.variant_id}) ` +
        `used key_hex=${c.key_hex} but subkeys.variants entry for id=${c.variant_id} has subkey_hex=${expected}`,
      );
    }
  }

  // Nonce examples (finding: IMPORTANT 5): every case above has a counter
  // byte <= 255, so an implementation that (mis)writes the counter into a
  // single byte would still pass every one of them, and only break in
  // production at ~2 GiB into a stream. Pin the boundary values explicitly,
  // including the full 32-bit counter, using one stated fixed prefix.
  const NONCE_EXAMPLES_PREFIX = STREAM_PREFIX_BY_VARIANT[1];
  const nonceExampleCounters = [0, 1, 255, 256, 65535, 65536, 4294967295];
  const nonceExamples = nonceExampleCounters.map((counter) => ({
    counter,
    is_final: counter === 4294967295,
    nonce_hex: hexOf(buildNonce(NONCE_EXAMPLES_PREFIX, counter, counter === 4294967295)),
  }));

  const stream = {
    production_chunk_size: CHUNK_SIZE,
    nonce_prefix_bytes: NONCE_PREFIX_BYTES,
    file_id_hex: hexOf(C.FILE_ID),
    cases: streamCases,
    nonce_examples_prefix_hex: hexOf(NONCE_EXAMPLES_PREFIX),
    nonce_examples: nonceExamples,
  };

  // --- Negative vectors (finding: IMPORTANT 6): pre-built malformed inputs so
  // every client encodes the same "rejected" behaviour instead of each
  // re-inventing (and possibly diverging on) its own negative tests. Reuses
  // the "exact_chunk_boundary" case's already-derived key/prefix/chunks
  // rather than inventing new plaintexts.
  const boundaryCase = streamCases.find((c) => c.name === "exact_chunk_boundary");
  const boundaryChunks = boundaryCase.chunks_hex.map((h) => Buffer.from(h, "hex"));
  const boundaryKey = C.hex(boundaryCase.key_hex);
  const boundaryPrefix = C.hex(boundaryCase.nonce_prefix_hex);

  // Reused for the cross-variant splice vector below: a real chunk that was
  // actually encrypted under variant 3's own key and nonce prefix.
  const variant3Case = streamCases.find((c) => c.name === "original_variant_multi_chunk_short_final");

  // Fresh encryption needed only for the splice-from-another-file vector:
  // none of the existing cases has a second fileId to pull a chunk from.
  const otherFileChunks = encryptStream(
    sodium, body(FIXTURE_CHUNK_SIZE * 2), boundaryKey, boundaryPrefix, OTHER_FILE_ID, 1, FIXTURE_CHUNK_SIZE,
  );

  const tamperedChunk0 = Uint8Array.from(boundaryChunks[0]);
  tamperedChunk0[0] ^= 0x01;

  const negative = {
    stream_truncated: {
      reason: "final chunk dropped from a 2-chunk stream - decrypt MUST reject truncation, not return a short plaintext",
      must_fail: true,
      key_hex: boundaryCase.key_hex,
      nonce_prefix_hex: boundaryCase.nonce_prefix_hex,
      file_id_hex: stream.file_id_hex,
      variant_id: boundaryCase.variant_id,
      chunks_hex: [boundaryChunks[0]].map(hexOf),
    },
    stream_reordered: {
      reason: "the 2 chunks of exact_chunk_boundary swapped - decrypt MUST reject reordering",
      must_fail: true,
      key_hex: boundaryCase.key_hex,
      nonce_prefix_hex: boundaryCase.nonce_prefix_hex,
      file_id_hex: stream.file_id_hex,
      variant_id: boundaryCase.variant_id,
      chunks_hex: [boundaryChunks[1], boundaryChunks[0]].map(hexOf),
    },
    stream_spliced_from_other_file: {
      reason: "chunk 0 was encrypted under a different fileId, same key/prefix/variant - AAD binding MUST reject the splice",
      must_fail: true,
      key_hex: boundaryCase.key_hex,
      nonce_prefix_hex: boundaryCase.nonce_prefix_hex,
      file_id_hex: stream.file_id_hex,
      other_file_id_hex: hexOf(OTHER_FILE_ID),
      variant_id: boundaryCase.variant_id,
      chunks_hex: [otherFileChunks[0], boundaryChunks[1]].map(hexOf),
    },
    stream_relabelled_as_other_variant: {
      reason: "the ENTIRE variant-3 stream (original_variant_multi_chunk_short_final, all 5 chunks), decrypted as though the whole file were variant 1. key_hex and nonce_prefix_hex here are variant 3's own - the exact key and prefix that actually encrypted every one of these chunks - and every chunk is presented at its true position, so decrypt derives the correct isFinal per chunk (chunk 0 at isFinal=false, matching how it was really sealed). Nothing here is spliced, truncated, or reordered: with the correct key, correct nonces, and correct final flags, only the claimed variant_id (1) differs from the variant that really encrypted the stream (3, see other_variant_id). That isolates the AAD's variant byte (fileId(16) || variantId(1)) as the sole thing that can make decrypt reject it. Note a chunk actually moved between variants would already fail on the key, since each variant derives a distinct subkey (spec §7.2) - this vector instead pins the AAD's specific, additional contribution: catching a correctly-keyed stream that is merely mislabelled.",
      must_fail: true,
      key_hex: variant3Case.key_hex,
      nonce_prefix_hex: variant3Case.nonce_prefix_hex,
      file_id_hex: stream.file_id_hex,
      other_variant_id: variant3Case.variant_id,
      variant_id: 1,
      chunks_hex: variant3Case.chunks_hex,
    },
    stream_empty_chunk_list: {
      reason: "zero chunks - decrypt MUST throw rather than return an empty plaintext (finding: IMPORTANT 2)",
      must_fail: true,
      key_hex: boundaryCase.key_hex,
      nonce_prefix_hex: boundaryCase.nonce_prefix_hex,
      file_id_hex: stream.file_id_hex,
      variant_id: boundaryCase.variant_id,
      chunks_hex: [],
    },
    stream_tampered_byte: {
      reason: "a single byte flipped in chunk 0 of exact_chunk_boundary - the AEAD tag MUST reject it",
      must_fail: true,
      key_hex: boundaryCase.key_hex,
      nonce_prefix_hex: boundaryCase.nonce_prefix_hex,
      file_id_hex: stream.file_id_hex,
      variant_id: boundaryCase.variant_id,
      chunks_hex: [tamperedChunk0, boundaryChunks[1]].map(hexOf),
    },
    keybox_wrong_wrapping_key: {
      reason: "master_key_by_kek's ciphertext opened with the recovery key instead of the KEK it was actually sealed under - the MAC MUST reject",
      must_fail: true,
      ciphertext_hex: keybox.master_key_by_kek.ciphertext_hex,
      nonce_hex: keybox.master_key_by_kek.nonce_hex,
      correct_wrapping_key_hex: keybox.master_key_by_kek.wrapping_key_hex,
      wrong_wrapping_key_hex: hexOf(C.RECOVERY_KEY),
    },
  };

  const safety = {
    iterations: 5200,
    version: 0,
    version_bytes: 2,
    version_encoding: "big-endian",
    identifier_encoding: "utf8",
    alice_bob: safetyNumber(sodium, alice.publicKey, C.ALICE_SUB, bob.publicKey, C.BOB_SUB),
    bob_alice_must_match: safetyNumber(sodium, bob.publicKey, C.BOB_SUB, alice.publicKey, C.ALICE_SUB),
    alice_mallory: safetyNumber(sodium, alice.publicKey, C.ALICE_SUB, mallory.publicKey, C.MALLORY_SUB),
    alice_digits: partyDigits(sodium, alice.publicKey, C.ALICE_SUB),
    bob_digits: partyDigits(sodium, bob.publicKey, C.BOB_SUB),
    mallory_digits: partyDigits(sodium, mallory.publicKey, C.MALLORY_SUB),
  };

  const vectors = {
    _README: "Generated by tools/vectors/generate.mjs. DO NOT EDIT BY HAND. Regenerate with `npm run generate`. A diff in this file is a WIRE FORMAT CHANGE.",
    spec: "docs/superpowers/specs/2026-07-25-mantel-protocol-v2-design.md",
    version: 1,
    kdf,
    subkeys,
    keybox,
    identity,
    stream,
    negative,
    safety_number: safety,
  };

  const here = dirname(fileURLToPath(import.meta.url));
  writeFileSync(join(here, "vectors.json"), JSON.stringify(vectors, null, 2) + "\n");
  console.log("wrote vectors.json");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
