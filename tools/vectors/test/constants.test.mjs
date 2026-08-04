import { describe, it, expect } from "vitest";
import * as C from "../src/constants.mjs";

describe("constants", () => {
  it("hex decodes to bytes", () => {
    expect(Array.from(C.hex("00ff10"))).toEqual([0, 255, 16]);
  });

  it("all key material is 32 bytes", () => {
    for (const name of ["MASTER_KEY", "RECOVERY_KEY", "COLLECTION_KEY", "FILE_KEY"]) {
      expect(C[name].length, name).toBe(32);
    }
  });

  it("salt is 16 bytes and fileId is 16 bytes", () => {
    expect(C.KDF_SALT.length).toBe(16);
    expect(C.FILE_ID.length).toBe(16);
  });

  it("seeds are 32 bytes and distinct", () => {
    const seeds = [C.ALICE_SEED, C.BOB_SEED, C.MALLORY_SEED];
    for (const s of seeds) expect(s.length).toBe(32);
    const asHex = seeds.map((s) => Buffer.from(s).toString("hex"));
    expect(new Set(asHex).size).toBe(3);
  });
});
