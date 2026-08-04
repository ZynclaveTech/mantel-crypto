package com.zynclave.familyalbum.cryptov2

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class IdentityBoxTest {

    private val ib = IdentityBox(testSodium)

    @Test
    fun keypairsMatchFixture() {
        val id = Vectors.section("identity")
        for (name in listOf("alice", "bob", "mallory")) {
            val party = id.getJSONObject(name)
            val kp = ib.keypair(unhex(party.getString("seed_hex")))
            assertEquals(party.getString("pub_hex"), hex(kp.publicKey), "$name pub")
            assertEquals(party.getString("priv_hex"), hex(kp.privateKey), "$name priv")
        }
    }

    @Test
    fun shareAliceToBobMatchesFixture() {
        val id = Vectors.section("identity")
        val alice = id.getJSONObject("alice")
        val bob = id.getJSONObject("bob")
        val share = id.getJSONObject("share_alice_to_bob")

        val ct = ib.share(
            key = unhex(share.getString("plaintext_hex")),
            nonce = unhex(share.getString("nonce_hex")),
            recipientPublicKey = unhex(bob.getString("pub_hex")),
            senderPrivateKey = unhex(alice.getString("priv_hex")),
        )
        assertEquals(share.getString("ciphertext_hex"), hex(ct))

        val back = ib.openShare(
            ciphertext = ct,
            nonce = unhex(share.getString("nonce_hex")),
            senderPublicKey = unhex(alice.getString("pub_hex")),
            recipientPrivateKey = unhex(bob.getString("priv_hex")),
        )
        assertEquals(share.getString("plaintext_hex"), hex(back))
    }

    /**
     * THE test this whole protocol rewrite exists for.
     *
     * Mallory is not a family member. She seals a collection key for Bob while
     * claiming to be Alice. Opening it against Alice's public key MUST fail.
     * Under v1 - which used an ephemeral, unauthenticated sender key - it
     * would have succeeded, and any member could substitute anyone's key.
     */
    @Test
    fun forgedShareClaimingAliceIsRejected() {
        val id = Vectors.section("identity")
        val alice = id.getJSONObject("alice")
        val bob = id.getJSONObject("bob")
        val forged = id.getJSONObject("forged_by_mallory_claiming_alice")
        assertEquals("alice", forged.getString("must_fail_to_open_as"))

        assertFailsWith<CryptoError.AuthenticationFailed> {
            ib.openShare(
                ciphertext = unhex(forged.getString("ciphertext_hex")),
                nonce = unhex(forged.getString("nonce_hex")),
                senderPublicKey = unhex(alice.getString("pub_hex")),
                recipientPrivateKey = unhex(bob.getString("priv_hex")),
            )
        }
    }

    /** The same forged envelope DOES open as mallory - proving it is well formed. */
    @Test
    fun forgedShareOpensAsItsRealSender() {
        val id = Vectors.section("identity")
        val bob = id.getJSONObject("bob")
        val mallory = id.getJSONObject("mallory")
        val forged = id.getJSONObject("forged_by_mallory_claiming_alice")

        val pt = ib.openShare(
            ciphertext = unhex(forged.getString("ciphertext_hex")),
            nonce = unhex(forged.getString("nonce_hex")),
            senderPublicKey = unhex(mallory.getString("pub_hex")),
            recipientPrivateKey = unhex(bob.getString("priv_hex")),
        )
        assertEquals(32, pt.size)
    }

    @Test
    fun rejectsWrongLengthKeyMaterial() {
        assertFailsWith<CryptoError.InvalidKeyLength>("keypair: wrong-length seed") {
            ib.keypair(ByteArray(31))
        }

        val id = Vectors.section("identity")
        val alice = id.getJSONObject("alice")
        val bob = id.getJSONObject("bob")
        val share = id.getJSONObject("share_alice_to_bob")
        val plaintext = unhex(share.getString("plaintext_hex"))
        val validNonce = unhex(share.getString("nonce_hex"))
        val validCiphertext = unhex(share.getString("ciphertext_hex"))
        val alicePriv = unhex(alice.getString("priv_hex"))
        val alicePub = unhex(alice.getString("pub_hex"))
        val bobPub = unhex(bob.getString("pub_hex"))
        val bobPriv = unhex(bob.getString("priv_hex"))

        assertFailsWith<CryptoError.InvalidKeyLength>("share: wrong-length recipientPublicKey") {
            ib.share(
                key = plaintext,
                nonce = validNonce,
                recipientPublicKey = ByteArray(16),
                senderPrivateKey = alicePriv,
            )
        }

        assertFailsWith<CryptoError.InvalidKeyLength>("share: wrong-length senderPrivateKey") {
            ib.share(
                key = plaintext,
                nonce = validNonce,
                recipientPublicKey = bobPub,
                senderPrivateKey = ByteArray(8),
            )
        }

        assertFailsWith<CryptoError.InvalidKeyLength>("openShare: wrong-length senderPublicKey") {
            ib.openShare(
                ciphertext = validCiphertext,
                nonce = validNonce,
                senderPublicKey = ByteArray(16),
                recipientPrivateKey = bobPriv,
            )
        }

        assertFailsWith<CryptoError.InvalidKeyLength>("openShare: wrong-length recipientPrivateKey") {
            ib.openShare(
                ciphertext = validCiphertext,
                nonce = validNonce,
                senderPublicKey = alicePub,
                recipientPrivateKey = ByteArray(8),
            )
        }

        // The wrapped key itself was the one key-typed parameter with no check.
        assertFailsWith<CryptoError.InvalidKeyLength>("share: wrong-length wrapped key") {
            ib.share(
                key = ByteArray(16),
                nonce = validNonce,
                recipientPublicKey = bobPub,
                senderPrivateKey = alicePriv,
            )
        }

        // Short ciphertext: without a guard this is NegativeArraySizeException,
        // not a CryptoError. At exactly TAG_BYTES it would authenticate and
        // return an empty collection key.
        assertFailsWith<CryptoError.InvalidInput> { ib.openShare(ByteArray(8), validNonce, alicePub, bobPriv) }
        assertFailsWith<CryptoError.InvalidInput>("openShare: tag-only ciphertext") {
            ib.openShare(ByteArray(WireConstants.TAG_BYTES), validNonce, alicePub, bobPriv)
        }

        assertFailsWith<CryptoError.InvalidNonceLength>("share: wrong-length nonce") {
            ib.share(
                key = plaintext,
                nonce = ByteArray(1),
                recipientPublicKey = bobPub,
                senderPrivateKey = alicePriv,
            )
        }
    }
}
