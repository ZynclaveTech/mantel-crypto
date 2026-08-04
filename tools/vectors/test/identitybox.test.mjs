import { describe, it, expect, beforeAll } from "vitest";
import { loadSodium } from "../src/sodium.mjs";
import { identityKeypair, shareKey, openSharedKey } from "../src/identitybox.mjs";
import { ALICE_SEED, BOB_SEED, MALLORY_SEED, COLLECTION_KEY } from "../src/constants.mjs";

let sodium, alice, bob, mallory;
const NONCE = Uint8Array.from(Buffer.from("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7", "hex"));

beforeAll(async () => {
  sodium = await loadSodium();
  alice = identityKeypair(sodium, ALICE_SEED);
  bob = identityKeypair(sodium, BOB_SEED);
  mallory = identityKeypair(sodium, MALLORY_SEED);
});

describe("identitybox", () => {
  it("derives a deterministic X25519 keypair from a seed", () => {
    const again = identityKeypair(sodium, ALICE_SEED);
    expect(Buffer.from(again.publicKey).toString("hex")).toBe(Buffer.from(alice.publicKey).toString("hex"));
    expect(alice.publicKey.length).toBe(32);
    expect(alice.privateKey.length).toBe(32);
  });

  it("alice shares a collection key that bob can open", () => {
    const ct = shareKey(sodium, COLLECTION_KEY, NONCE, bob.publicKey, alice.privateKey);
    const pt = openSharedKey(sodium, ct, NONCE, alice.publicKey, bob.privateKey);
    expect(Buffer.from(pt).toString("hex")).toBe(Buffer.from(COLLECTION_KEY).toString("hex"));
  });

  // The spec §11 negative test that matters most: this is the v1 defect.
  it("rejects a share that claims to be from alice but was sealed by mallory", () => {
    const forged = shareKey(sodium, COLLECTION_KEY, NONCE, bob.publicKey, mallory.privateKey);
    expect(() => openSharedKey(sodium, forged, NONCE, alice.publicKey, bob.privateKey)).toThrow();
  });

  it("rejects opening with the wrong recipient key", () => {
    const ct = shareKey(sodium, COLLECTION_KEY, NONCE, bob.publicKey, alice.privateKey);
    expect(() => openSharedKey(sodium, ct, NONCE, alice.publicKey, mallory.privateKey)).toThrow();
  });

  it("rejects a tampered ciphertext", () => {
    const ct = shareKey(sodium, COLLECTION_KEY, NONCE, bob.publicKey, alice.privateKey);
    ct[0] ^= 0x01;
    expect(() => openSharedKey(sodium, ct, NONCE, alice.publicKey, bob.privateKey)).toThrow();
  });
});
