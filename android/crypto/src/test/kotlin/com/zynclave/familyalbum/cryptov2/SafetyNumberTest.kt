package com.zynclave.familyalbum.cryptov2

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SafetyNumberTest {

    private val sn = SafetyNumber(testSodium)

    @Test
    fun aliceBobMatchesFixture() {
        val id = Vectors.section("identity")
        val f = Vectors.section("safety_number")
        val alice = id.getJSONObject("alice")
        val bob = id.getJSONObject("bob")

        val computed = sn.compute(
            unhex(alice.getString("pub_hex")), alice.getString("sub"),
            unhex(bob.getString("pub_hex")), bob.getString("sub"),
        )
        assertEquals(f.getString("alice_bob"), computed)
        assertEquals(60, computed.length)
        assertTrue(computed.all { it.isDigit() })
    }

    /** Both parties read the number off their own screens, so order cannot matter. */
    @Test
    fun isSymmetric() {
        val id = Vectors.section("identity")
        val f = Vectors.section("safety_number")
        val alice = id.getJSONObject("alice")
        val bob = id.getJSONObject("bob")

        val ab = sn.compute(
            unhex(alice.getString("pub_hex")), alice.getString("sub"),
            unhex(bob.getString("pub_hex")), bob.getString("sub"),
        )
        val ba = sn.compute(
            unhex(bob.getString("pub_hex")), bob.getString("sub"),
            unhex(alice.getString("pub_hex")), alice.getString("sub"),
        )
        assertEquals(ab, ba)
        assertEquals(f.getString("bob_alice_must_match"), ba)
    }

    /** The fixture pins each party's own 30-digit half. */
    @Test
    fun perPartyDigitsMatchFixture() {
        val id = Vectors.section("identity")
        val f = Vectors.section("safety_number")
        for ((party, key) in listOf("alice" to "alice_digits", "bob" to "bob_digits", "mallory" to "mallory_digits")) {
            val p = id.getJSONObject(party)
            val digits = sn.digitsFor(unhex(p.getString("pub_hex")), p.getString("sub"))
            assertEquals(f.getString(key), digits, "$party digits")
            assertEquals(30, digits.length)
        }

        // All 18 fixture groups happen to be >= 10000, so digitsFor's
        // .padStart(5, '0') never actually pads for alice, bob or mallory:
        // deleting it leaves this suite green while roughly half of real users
        // get a short safety number. This key/identifier pair was searched for
        // precisely because it hits that padding branch - its fourth group is
        // 3252, which renders as "03252" only if the padding is present.
        // Structural assertion on length by design: a hardcoded expected string
        // computed from this same implementation would be circular.
        val paddingKey = ByteArray(WireConstants.KEY_BYTES) { 0x01 }
        val paddingId = "00000000-0000-4000-8000-000000000000"
        val padded = sn.digitsFor(paddingKey, paddingId)
        assertEquals(30, padded.length, "a group below 10000 must still render as 5 digits")
        assertTrue(padded.all { it.isDigit() })
    }

    /**
     * Byte-identical keys have no byte order, so the tie-break falls back to
     * comparing rendered digit strings. That fallback must still be
     * symmetric regardless of argument order - this is what issue #88 item 3
     * calls out: the old `a.size <= b.size` tail always returned true for
     * equal-length identical keys, so `compute(K, x, K, y)` and
     * `compute(K, y, K, x)` produced different 60-digit numbers.
     */
    @Test
    fun isSymmetricWhenKeysAreByteIdentical() {
        val key = ByteArray(WireConstants.KEY_BYTES) { 0x42 }
        val xy = sn.compute(key, "member-x", key, "member-y")
        val yx = sn.compute(key, "member-y", key, "member-x")
        assertEquals(xy, yx)
        assertEquals(60, xy.length)
    }

    /** A substituted key must change the number - the whole point of showing it. */
    @Test
    fun impostorKeyChangesTheNumber() {
        val id = Vectors.section("identity")
        val f = Vectors.section("safety_number")
        val alice = id.getJSONObject("alice")
        val mallory = id.getJSONObject("mallory")

        val computed = sn.compute(
            unhex(alice.getString("pub_hex")), alice.getString("sub"),
            unhex(mallory.getString("pub_hex")), mallory.getString("sub"),
        )
        assertEquals(f.getString("alice_mallory"), computed)
        assertNotEquals(f.getString("alice_bob"), computed)
    }

    @Test
    fun rejectsWrongKeyLength() {
        assertFailsWith<CryptoError.InvalidKeyLength> {
            sn.compute(ByteArray(31), "a", ByteArray(32), "b")
        }
        assertFailsWith<CryptoError.InvalidKeyLength> {
            sn.digitsFor(ByteArray(31), "a")
        }
    }
}
