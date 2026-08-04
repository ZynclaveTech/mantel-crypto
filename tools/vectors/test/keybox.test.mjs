import { describe, it, expect, beforeAll } from "vitest";
import { loadSodium } from "../src/sodium.mjs";
import { sealKey, openKey, NONCE_BYTES } from "../src/keybox.mjs";
import { MASTER_KEY, RECOVERY_KEY, COLLECTION_KEY } from "../src/constants.mjs";

let sodium;
const NONCE = Uint8Array.from(Buffer.from("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7", "hex"));

beforeAll(async () => {
  sodium = await loadSodium();
});

describe("keybox", () => {
  it("uses a 24-byte nonce", () => {
    expect(NONCE_BYTES).toBe(24);
    expect(NONCE.length).toBe(24);
  });

  it("round-trips a key", () => {
    const ct = sealKey(sodium, MASTER_KEY, NONCE, RECOVERY_KEY);
    const pt = openKey(sodium, ct, NONCE, RECOVERY_KEY);
    expect(Buffer.from(pt).toString("hex")).toBe(Buffer.from(MASTER_KEY).toString("hex"));
  });

  it("appends a 16-byte MAC", () => {
    const ct = sealKey(sodium, MASTER_KEY, NONCE, RECOVERY_KEY);
    expect(ct.length).toBe(MASTER_KEY.length + 16);
  });

  it("rejects the wrong wrapping key", () => {
    const ct = sealKey(sodium, MASTER_KEY, NONCE, RECOVERY_KEY);
    expect(() => openKey(sodium, ct, NONCE, COLLECTION_KEY)).toThrow();
  });

  it("rejects a tampered ciphertext", () => {
    const ct = sealKey(sodium, MASTER_KEY, NONCE, RECOVERY_KEY);
    ct[0] ^= 0x01;
    expect(() => openKey(sodium, ct, NONCE, RECOVERY_KEY)).toThrow();
  });

  it("rejects a tampered nonce", () => {
    const ct = sealKey(sodium, MASTER_KEY, NONCE, RECOVERY_KEY);
    const bad = Uint8Array.from(NONCE);
    bad[0] ^= 0x01;
    expect(() => openKey(sodium, ct, bad, RECOVERY_KEY)).toThrow();
  });
});
