import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadSodium } from "../src/sodium.mjs";
import {
  buildNonce, buildAAD, encryptStream, decryptStream,
  NONCE_PREFIX_BYTES, TAG_BYTES,
} from "../src/stream.mjs";
import { deriveSubkey, VARIANT_CONTEXT } from "../src/kdf.mjs";
import { FILE_KEY, FILE_ID } from "../src/constants.mjs";

let sodium;
const PREFIX = Uint8Array.from(Buffer.from("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2", "hex")); // 19 bytes, variant 1
const PREFIX_2 = Uint8Array.from(Buffer.from("e1e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f3", "hex")); // 19 bytes, variant 2
const SMALL = 64; // small chunk size keeps tests fast; the wire value is 8 MiB

const vectorsPath = join(dirname(fileURLToPath(import.meta.url)), "..", "vectors.json");
const vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));

beforeAll(async () => {
  sodium = await loadSodium();
});

const body = (n) => Uint8Array.from({ length: n }, (_, i) => i % 251);

describe("stream nonce and aad", () => {
  it("nonce is prefix || counter(4, big-endian) || finalFlag(1)", () => {
    expect(PREFIX.length).toBe(NONCE_PREFIX_BYTES);
    const n = buildNonce(PREFIX, 258, true);
    expect(n.length).toBe(24);
    expect(Array.from(n.slice(0, 19))).toEqual(Array.from(PREFIX));
    expect(Array.from(n.slice(19, 23))).toEqual([0, 0, 1, 2]); // 258 big-endian
    expect(n[23]).toBe(0x01);
  });

  it("non-final chunks carry a 0x00 flag", () => {
    expect(buildNonce(PREFIX, 0, false)[23]).toBe(0x00);
  });

  it("aad is fileId(16) || variantId(1)", () => {
    const aad = buildAAD(FILE_ID, 2);
    expect(aad.length).toBe(17);
    expect(aad[16]).toBe(2);
  });
});

describe("stream round trip", () => {
  it("round-trips a single short chunk", () => {
    const pt = body(10);
    const chunks = encryptStream(sodium, pt, FILE_KEY, PREFIX, FILE_ID, 1, SMALL);
    expect(chunks.length).toBe(1);
    expect(Buffer.from(decryptStream(sodium, chunks, FILE_KEY, PREFIX, FILE_ID, 1)).toString("hex"))
      .toBe(Buffer.from(pt).toString("hex"));
  });

  it("round-trips multiple chunks", () => {
    const pt = body(SMALL * 3 + 7);
    const chunks = encryptStream(sodium, pt, FILE_KEY, PREFIX, FILE_ID, 1, SMALL);
    expect(chunks.length).toBe(4);
    expect(Buffer.from(decryptStream(sodium, chunks, FILE_KEY, PREFIX, FILE_ID, 1)).toString("hex"))
      .toBe(Buffer.from(pt).toString("hex"));
  });

  it("round-trips an exact chunk-boundary length", () => {
    const pt = body(SMALL * 2);
    const chunks = encryptStream(sodium, pt, FILE_KEY, PREFIX, FILE_ID, 1, SMALL);
    expect(chunks.length).toBe(2);
    expect(Buffer.from(decryptStream(sodium, chunks, FILE_KEY, PREFIX, FILE_ID, 1)).toString("hex"))
      .toBe(Buffer.from(pt).toString("hex"));
  });

  it("each ciphertext chunk carries a 16-byte tag", () => {
    const chunks = encryptStream(sodium, body(SMALL + 5), FILE_KEY, PREFIX, FILE_ID, 1, SMALL);
    expect(chunks[0].length).toBe(SMALL + TAG_BYTES);
    expect(chunks[1].length).toBe(5 + TAG_BYTES);
  });

  // The whole reason for choosing STREAM over secretstream (spec §7.1).
  it("supports random access - a middle chunk decrypts alone", () => {
    const pt = body(SMALL * 3);
    const chunks = encryptStream(sodium, pt, FILE_KEY, PREFIX, FILE_ID, 1, SMALL);
    const middle = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, chunks[1], buildAAD(FILE_ID, 1), buildNonce(PREFIX, 1, false), FILE_KEY,
    );
    expect(Buffer.from(middle).toString("hex")).toBe(Buffer.from(pt.slice(SMALL, SMALL * 2)).toString("hex"));
  });
});

describe("stream negative cases", () => {
  it("rejects a truncated stream - dropping the final chunk", () => {
    const chunks = encryptStream(sodium, body(SMALL * 3), FILE_KEY, PREFIX, FILE_ID, 1, SMALL);
    expect(() => decryptStream(sodium, chunks.slice(0, -1), FILE_KEY, PREFIX, FILE_ID, 1)).toThrow();
  });

  it("rejects reordered chunks", () => {
    const chunks = encryptStream(sodium, body(SMALL * 3), FILE_KEY, PREFIX, FILE_ID, 1, SMALL);
    const swapped = [chunks[1], chunks[0], chunks[2]];
    expect(() => decryptStream(sodium, swapped, FILE_KEY, PREFIX, FILE_ID, 1)).toThrow();
  });

  it("rejects a chunk spliced in from another file", () => {
    // Different fileId AND a different key, since in the real key hierarchy
    // every file has its own file key wrapped under the collection key - two
    // different files never share a raw content key (finding: Minor).
    const OTHER_FILE_KEY = Uint8Array.from(Buffer.from("05".repeat(32), "hex"));
    const other = Uint8Array.from(Buffer.from("ffffffffffffffffffffffffffffffff", "hex"));
    const a = encryptStream(sodium, body(SMALL * 2), FILE_KEY, PREFIX, FILE_ID, 1, SMALL);
    const b = encryptStream(sodium, body(SMALL * 2), OTHER_FILE_KEY, PREFIX, other, 1, SMALL);
    expect(() => decryptStream(sodium, [b[0], a[1]], FILE_KEY, PREFIX, FILE_ID, 1)).toThrow();
  });

  it("rejects a chunk from a different variant of the same file", () => {
    // CRITICAL FIX: each variant gets its own derived subkey and its own
    // nonce prefix, exactly as generate.mjs now does - encrypting both
    // variants under the raw FILE_KEY and a shared prefix is precisely the
    // two-time-pad pattern this test is supposed to guard against.
    const key1 = deriveSubkey(sodium, FILE_KEY, 1, VARIANT_CONTEXT);
    const key2 = deriveSubkey(sodium, FILE_KEY, 2, VARIANT_CONTEXT);
    const thumb = encryptStream(sodium, body(SMALL * 2), key1, PREFIX, FILE_ID, 1, SMALL);
    const preview = encryptStream(sodium, body(SMALL * 2), key2, PREFIX_2, FILE_ID, 2, SMALL);
    expect(() => decryptStream(sodium, [preview[0], thumb[1]], key1, PREFIX, FILE_ID, 1)).toThrow();
  });

  it("rejects a tampered chunk", () => {
    const chunks = encryptStream(sodium, body(SMALL * 2), FILE_KEY, PREFIX, FILE_ID, 1, SMALL);
    chunks[0][0] ^= 0x01;
    expect(() => decryptStream(sodium, chunks, FILE_KEY, PREFIX, FILE_ID, 1)).toThrow();
  });

  // IMPORTANT 2: encrypt always emits >= 1 chunk (Math.max(1, ...)), so a
  // zero-chunk list is never a valid encryption of anything - it means every
  // object was deleted - and MUST throw rather than decrypt to zero bytes.
  it("rejects an empty chunk list", () => {
    expect(() => decryptStream(sodium, [], FILE_KEY, PREFIX, FILE_ID, 1)).toThrow();
  });
});

describe("stream/subkeys composition (fixture)", () => {
  // CRITICAL: the check that would have caught the original bug. Two
  // independently-correct modules (kdf.mjs's subkey derivation and
  // stream.mjs's encryption) can still compose incorrectly if generate.mjs
  // never wires one into the other. Assert directly against the committed
  // vectors.json - the actual frozen contract clients read - not just
  // against a fresh re-derivation that would trivially agree with itself.
  it("every stream case's key_hex matches its variant's published subkey", () => {
    expect(vectors.stream.cases.length).toBeGreaterThan(0);
    for (const c of vectors.stream.cases) {
      const expected = vectors.subkeys.variants[c.variant_id - 1].subkey_hex;
      expect(c.key_hex).toBe(expected);
    }
  });

  it("two cases sharing a file_id but differing in variant_id use different keys and prefixes", () => {
    // All stream.cases share the one top-level file_id_hex. Find two cases
    // with different variant_id and confirm they were NOT encrypted as a
    // two-time pad (the CRITICAL bug this whole fix is about).
    const v1 = vectors.stream.cases.find((c) => c.variant_id === 1);
    const v2 = vectors.stream.cases.find((c) => c.variant_id === 2);
    expect(v1).toBeTruthy();
    expect(v2).toBeTruthy();
    expect(v1.key_hex).not.toBe(v2.key_hex);
    expect(v1.nonce_prefix_hex).not.toBe(v2.nonce_prefix_hex);
  });
});
