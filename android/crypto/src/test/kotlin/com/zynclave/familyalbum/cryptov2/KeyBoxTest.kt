package com.zynclave.familyalbum.cryptov2

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class KeyBoxTest {

    private val box = KeyBox(testSodium)

    /**
     * The fixture pins every wrap site in the key hierarchy: master key under
     * the KEK, master key under the recovery key (the second, independent
     * unlock path), identity private key, collection key, file key, and the
     * photo metadata blob.
     */
    @Test
    fun everyWrapSiteMatchesFixture() {
        val keybox = Vectors.section("keybox")
        var checked = 0
        for (site in keybox.keys()) {
            val entry = keybox.getJSONObject(site)
            val plaintext = when {
                entry.has("plaintext_hex") -> unhex(entry.getString("plaintext_hex"))
                entry.has("plaintext_utf8") -> entry.getString("plaintext_utf8").toByteArray(Charsets.UTF_8)
                else -> error("wrap site '$site' has no plaintext")
            }
            val nonce = unhex(entry.getString("nonce_hex"))
            val key = unhex(entry.getString("wrapping_key_hex"))

            val ct = box.seal(plaintext, nonce, key)
            assertEquals(entry.getString("ciphertext_hex"), hex(ct), "seal mismatch at '$site'")
            assertEquals(hex(plaintext), hex(box.open(ct, nonce, key)), "open mismatch at '$site'")
            checked++
        }
        assertTrue(checked >= 6, "expected at least 6 wrap sites, checked $checked")
    }

    /** The fixture ships this so both platforms agree on what "rejected" means. */
    @Test
    fun fixtureWrongWrappingKeyIsRejected() {
        val c = Vectors.section("negative").getJSONObject("keybox_wrong_wrapping_key")
        assertTrue(c.getBoolean("must_fail"))
        assertFailsWith<CryptoError> {
            box.open(
                unhex(c.getString("ciphertext_hex")),
                unhex(c.getString("nonce_hex")),
                unhex(c.getString("wrong_wrapping_key_hex")),
            )
        }
    }

    @Test
    fun correctKeyFromTheNegativeVectorStillOpens() {
        val c = Vectors.section("negative").getJSONObject("keybox_wrong_wrapping_key")
        // Proves the negative vector fails for the RIGHT reason - the
        // ciphertext is valid, only the key is wrong.
        val pt = box.open(
            unhex(c.getString("ciphertext_hex")),
            unhex(c.getString("nonce_hex")),
            unhex(c.getString("correct_wrapping_key_hex")),
        )
        // The negative vector is master_key_by_kek's ciphertext/nonce/key
        // verbatim, so the recovered plaintext is pinned byte for byte rather
        // than merely "not empty".
        val site = Vectors.section("keybox").getJSONObject("master_key_by_kek")
        assertEquals(site.getString("ciphertext_hex"), c.getString("ciphertext_hex"))
        assertEquals(site.getString("nonce_hex"), c.getString("nonce_hex"))
        assertEquals(site.getString("wrapping_key_hex"), c.getString("correct_wrapping_key_hex"))
        assertEquals(site.getString("plaintext_hex"), hex(pt))
    }

    @Test
    fun tamperedCiphertextIsRejected() {
        val e = Vectors.section("keybox").getJSONObject("file_key_by_collection")
        val ct = unhex(e.getString("ciphertext_hex"))
        ct[0] = (ct[0].toInt() xor 0x01).toByte()
        assertFailsWith<CryptoError> {
            box.open(ct, unhex(e.getString("nonce_hex")), unhex(e.getString("wrapping_key_hex")))
        }
    }

    @Test
    fun tamperedNonceIsRejected() {
        val e = Vectors.section("keybox").getJSONObject("file_key_by_collection")
        val nonce = unhex(e.getString("nonce_hex"))
        nonce[0] = (nonce[0].toInt() xor 0x01).toByte()
        assertFailsWith<CryptoError> {
            box.open(unhex(e.getString("ciphertext_hex")), nonce, unhex(e.getString("wrapping_key_hex")))
        }
    }

    @Test
    fun rejectsWrongNonceLength() {
        assertFailsWith<CryptoError.InvalidNonceLength> {
            box.seal(byteArrayOf(1, 2, 3), ByteArray(23), ByteArray(32))
        }

        // A bare 16-byte tag authenticates and would unwrap to ByteArray(0) -
        // an EMPTY MASTER KEY returned as success. This class only ever wraps
        // key material, so zero-length output is never a legitimate result.
        assertFailsWith<CryptoError.InvalidInput>("tag-only ciphertext must be rejected") {
            box.open(ByteArray(WireConstants.TAG_BYTES), ByteArray(24), ByteArray(32))
        }

        // seal() must refuse to produce exactly the ciphertext open() just
        // rejected above - otherwise a successful seal(ByteArray(0)) would
        // persist a tag-only ciphertext that can never be opened again.
        assertFailsWith<CryptoError.InvalidInput>("empty plaintext must be rejected") {
            box.seal(ByteArray(0), ByteArray(24), ByteArray(32))
        }
    }
}
