import { describe, it, expect, beforeAll } from "vitest";
import { loadSodium } from "../src/sodium.mjs";
import { safetyNumber } from "../src/safetynumber.mjs";
import { identityKeypair } from "../src/identitybox.mjs";
import { ALICE_SEED, BOB_SEED, MALLORY_SEED, ALICE_SUB, BOB_SUB, MALLORY_SUB } from "../src/constants.mjs";

let sodium, alice, bob, mallory;
beforeAll(async () => {
  sodium = await loadSodium();
  alice = identityKeypair(sodium, ALICE_SEED);
  bob = identityKeypair(sodium, BOB_SEED);
  mallory = identityKeypair(sodium, MALLORY_SEED);
});

describe("safetyNumber", () => {
  it("is exactly 60 decimal digits", () => {
    const sn = safetyNumber(sodium, alice.publicKey, ALICE_SUB, bob.publicKey, BOB_SUB);
    expect(sn).toMatch(/^[0-9]{60}$/);
  });

  // Both parties must read the same number off their screens, so argument
  // order cannot matter.
  it("is symmetric", () => {
    const ab = safetyNumber(sodium, alice.publicKey, ALICE_SUB, bob.publicKey, BOB_SUB);
    const ba = safetyNumber(sodium, bob.publicKey, BOB_SUB, alice.publicKey, ALICE_SUB);
    expect(ab).toBe(ba);
  });

  it("changes when a party's key changes", () => {
    const real = safetyNumber(sodium, alice.publicKey, ALICE_SUB, bob.publicKey, BOB_SUB);
    // Mallory's own sub (finding: IMPORTANT 4) - not BOB_SUB borrowed from
    // bob, which would make this fixture unreproducible by a client that
    // only ever sees mallory's real identity.
    const impostor = safetyNumber(sodium, alice.publicKey, ALICE_SUB, mallory.publicKey, MALLORY_SUB);
    expect(impostor).not.toBe(real);
  });

  it("changes when a sub changes even if keys do not", () => {
    const a = safetyNumber(sodium, alice.publicKey, ALICE_SUB, bob.publicKey, BOB_SUB);
    const b = safetyNumber(sodium, alice.publicKey, ALICE_SUB, bob.publicKey, "different-sub");
    expect(a).not.toBe(b);
  });

  it("is deterministic", () => {
    const a = safetyNumber(sodium, alice.publicKey, ALICE_SUB, bob.publicKey, BOB_SUB);
    const b = safetyNumber(sodium, alice.publicKey, ALICE_SUB, bob.publicKey, BOB_SUB);
    expect(a).toBe(b);
  });
});
