import { describe, it, expect, beforeAll } from "vitest";
import { loadSodium } from "../src/sodium.mjs";
import { deriveKEK, deriveLoginKey, deriveSubkey, ARGON2ID_TIERS } from "../src/kdf.mjs";
import { PASSWORD, KDF_SALT, FILE_KEY } from "../src/constants.mjs";

let sodium;
beforeAll(async () => {
  sodium = await loadSodium();
});

describe("kdf", () => {
  it("exposes exactly the three tiers from the spec", () => {
    expect(ARGON2ID_TIERS.map((t) => t.name)).toEqual(["default", "mid", "low"]);
    expect(ARGON2ID_TIERS[0]).toMatchObject({ memlimit: 268435456, opslimit: 4 });
    expect(ARGON2ID_TIERS[1]).toMatchObject({ memlimit: 134217728, opslimit: 6 });
    expect(ARGON2ID_TIERS[2]).toMatchObject({ memlimit: 67108864, opslimit: 8 });
  });

  it("derives a 32-byte KEK deterministically", () => {
    const t = ARGON2ID_TIERS[2]; // low tier keeps the test fast
    const a = deriveKEK(sodium, PASSWORD, KDF_SALT, t.memlimit, t.opslimit);
    const b = deriveKEK(sodium, PASSWORD, KDF_SALT, t.memlimit, t.opslimit);
    expect(a.length).toBe(32);
    expect(Buffer.from(a).toString("hex")).toBe(Buffer.from(b).toString("hex"));
  });

  it("a different tier yields a different KEK", () => {
    const lo = ARGON2ID_TIERS[2];
    const mid = ARGON2ID_TIERS[1];
    const a = deriveKEK(sodium, PASSWORD, KDF_SALT, lo.memlimit, lo.opslimit);
    const b = deriveKEK(sodium, PASSWORD, KDF_SALT, mid.memlimit, mid.opslimit);
    expect(Buffer.from(a).toString("hex")).not.toBe(Buffer.from(b).toString("hex"));
  });

  it("loginKey is a 32-byte subkey of the KEK, not the KEK itself", () => {
    const t = ARGON2ID_TIERS[2];
    const kek = deriveKEK(sodium, PASSWORD, KDF_SALT, t.memlimit, t.opslimit);
    const login = deriveLoginKey(sodium, kek);
    expect(login.length).toBe(32);
    expect(Buffer.from(login).toString("hex")).not.toBe(Buffer.from(kek).toString("hex"));
  });

  it("variant subkeys are distinct per id", () => {
    const ids = [1, 2, 3].map((id) => Buffer.from(deriveSubkey(sodium, FILE_KEY, id, "mantelFV")).toString("hex"));
    expect(new Set(ids).size).toBe(3);
    for (const k of ids) expect(k.length).toBe(64);
  });
});
