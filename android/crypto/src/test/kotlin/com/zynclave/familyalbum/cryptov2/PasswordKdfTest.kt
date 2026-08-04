package com.zynclave.familyalbum.cryptov2

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class PasswordKdfTest {

    private val kdf = PasswordKdf(testSodium)

    /**
     * All three Argon2id tiers are contract, not just the default: the spec
     * stores the parameters PER USER, so a device enrolled at 64 MiB must
     * still log in after the default is raised.
     */
    @Test
    fun allArgon2idTiersMatchFixture() {
        val tiers = Vectors.array("kdf")
        assertEquals(3, tiers.size)
        for (t in tiers) {
            val tierName = t.getString("tier")
            val kek = kdf.deriveKek(
                password = t.getString("password"),
                salt = unhex(t.getString("salt_hex")),
                memlimit = t.getLong("memlimit"),
                opslimit = t.getLong("opslimit"),
            )
            assertEquals(t.getString("kek_hex"), hex(kek), "KEK mismatch at tier $tierName")
        }
    }

    /**
     * Split out from [allArgon2idTiersMatchFixture] for the same reason
     * [tiersMatchTheFixtureLadder] was: this is the assertion behind the
     * whole reason `deriveKek` whitelists at all, and it needs no Argon2id
     * work, so it must not sit behind three real derivations at 256/128/64
     * MiB where an allocation failure on a constrained runner would skip it
     * entirely. Mirrors iOS's `testUnapprovedKDFParametersAreRejected`.
     *
     * The ladder is a whitelist, not documentation. Per spec 5.3 these
     * parameters arrive from an unauthenticated endpoint, so an operator
     * serving mem=8KiB/ops=1 would otherwise get the client to derive a weak
     * KEK and hand the resulting loginKey to Cognito - one cheap Argon2id
     * inversion away from the plaintext password.
     */
    @Test
    fun unapprovedKdfParametersAreRejected() {
        assertFailsWith<CryptoError.UnapprovedKdfParameters>("weak Argon2id parameters must be rejected") {
            kdf.deriveKek(
                password = "correct horse battery staple",
                salt = ByteArray(WireConstants.SALT_BYTES),
                memlimit = 8192L,
                opslimit = 1L,
            )
        }

        // DO NOT DELETE THIS CASE. 64 MiB is the ladder's memory floor and 4
        // is its ops floor, but no tier PAIRS them - so this is the only
        // input that distinguishes an exact-pair whitelist from a floor check
        // like `memlimit >= 64 MiB && opslimit >= 4`, which would accept it
        // while being strictly weaker than every real tier. The 8KiB/1 case
        // above is rejected by both, so it cannot tell them apart.
        assertFailsWith<CryptoError.UnapprovedKdfParameters>(
            "64 MiB/4 pairs the ladder's two floors but is not itself a tier - a bounds " +
                "check would wrongly accept it",
        ) {
            kdf.deriveKek(
                password = "correct horse battery staple",
                salt = ByteArray(WireConstants.SALT_BYTES),
                memlimit = 64L * 1024 * 1024,
                opslimit = 4L,
            )
        }
    }

    /**
     * Split out from [allArgon2idTiersMatchFixture] so pinning
     * [PasswordKdf.TIERS] against the fixture ladder does not sit behind
     * three real Argon2id derivations at 256/128/64 MiB. This is pure data
     * comparison - no crypto - so it does not need to be there: the
     * original shape interleaved each tier's membership check right after
     * that same tier's real derivation, so a derivation failure (a changed
     * tier throwing from deriveKek, or an allocation failure at 256 MiB on
     * a constrained CI container) would abort the loop before the
     * membership check for that tier - and every tier after it - ever ran.
     * Same masking shape the iOS core's equivalent test had
     * (`PasswordKDFTests.testAllArgon2idTiersMatchFixture`, now split into
     * `testTiersMatchTheFixtureLadder`).
     */
    @Test
    fun tiersMatchTheFixtureLadder() {
        val tiers = Vectors.array("kdf")
        assertEquals(3, tiers.size)
        // TIERS holds the parameters production actually enrols users with, but
        // deriveKek in allArgon2idTiersMatchFixture is called with memlimit/opslimit
        // read straight from the fixture, never from TIERS. Without this, a typo in
        // TIERS would compile and pass this whole suite silently while real devices
        // derived a KEK that does not match the protocol.
        assertEquals(3, PasswordKdf.TIERS.size, "TIERS must have exactly the 3 tiers the fixture pins")
        for (t in tiers) {
            val tierName = t.getString("tier")
            val constantTier = PasswordKdf.TIERS.find { it.name == tierName }
                ?: throw AssertionError("PasswordKdf.TIERS has no entry named \"$tierName\"")
            assertEquals(t.getLong("memlimit"), constantTier.memlimit, "TIERS memlimit mismatch at tier $tierName")
            assertEquals(t.getLong("opslimit"), constantTier.opslimit, "TIERS opslimit mismatch at tier $tierName")
        }
    }

    @Test
    fun loginKeyMatchesFixture() {
        for (t in Vectors.array("kdf")) {
            val kek = unhex(t.getString("kek_hex"))
            val login = kdf.deriveLoginKey(kek)
            assertEquals(t.getString("login_key_hex"), hex(login))
            assertEquals(t.getString("login_key_b64"), Base64.getEncoder().encodeToString(login))
            // If these matched, the server would effectively hold the KEK.
            assertNotEquals(hex(kek), hex(login))
        }
    }

    @Test
    fun variantSubkeysMatchFixture() {
        val sk = Vectors.section("subkeys")
        val fileKey = unhex(sk.getString("file_key_hex"))
        val context = sk.getString("context")
        for (v in Vectors.objects(sk.getJSONArray("variants"))) {
            val derived = kdf.deriveSubkey(fileKey, v.getLong("id"), context)
            assertEquals(v.getString("subkey_hex"), hex(derived), "subkey mismatch for ${v.getString("name")}")

            // The production helper must produce the same bytes as the raw
            // derivation with the fixture's context: without it, VARIANT_CONTEXT
            // has no caller in src/main and every variant would be encrypted
            // under the raw file key - a recoverable two-time pad.
            val viaHelper = kdf.deriveVariantKey(fileKey, v.getInt("id"))
            assertEquals(
                v.getString("subkey_hex"), hex(viaHelper),
                "deriveVariantKey mismatch for ${v.getString("name")}",
            )
        }

        assertFailsWith<CryptoError.InvalidInput>("variantId 0 must be rejected") {
            kdf.deriveVariantKey(fileKey, 0)
        }
        assertFailsWith<CryptoError.InvalidInput>("variantId 4 must be rejected") {
            kdf.deriveVariantKey(fileKey, WireConstants.VARIANT_ORIGINAL + 1)
        }
    }

    @Test
    fun rejectsWrongSizedKey() {
        assertFailsWith<CryptoError.InvalidKeyLength> { kdf.deriveLoginKey(ByteArray(31)) }
    }

    @Test
    fun rejectsContextThatIsNotEightBytes() {
        assertFailsWith<CryptoError.InvalidInput> { kdf.deriveSubkey(ByteArray(32), 1, "short") }
    }
}
