package com.zynclave.familyalbum.cryptov2

import com.goterl.lazysodium.LazySodium

/**
 * X25519 + XSalsa20-Poly1305 AUTHENTICATED sharing (crypto_box).
 *
 * `crypto_box_seal` is deliberately NOT used anywhere in this protocol.
 * Anonymous sealing authenticates nothing about the sender, which is exactly
 * the v1 defect: collection keys arrived in envelopes sealed with an ephemeral
 * key, so the recipient could not tell who produced them, and any member could
 * overwrite anyone's content key.
 *
 * With crypto_box, `openShare` succeeds only if the envelope was produced by
 * the claimed sender's identity key. Forging a key delivery is impossible
 * rather than merely disallowed.
 */
class IdentityBox(private val sodium: LazySodium) {

    class KeyPair(val publicKey: ByteArray, val privateKey: ByteArray)

    /** Deterministic X25519 keypair from a 32-byte seed. */
    fun keypair(seed: ByteArray): KeyPair {
        if (seed.size != WireConstants.KEY_BYTES) {
            throw CryptoError.InvalidKeyLength(WireConstants.KEY_BYTES, seed.size)
        }
        val pk = ByteArray(WireConstants.KEY_BYTES)
        val sk = ByteArray(WireConstants.KEY_BYTES)
        if (!sodium.cryptoBoxSeedKeypair(pk, sk, seed)) {
            throw CryptoError.InvalidInput("box keypair derivation failed")
        }
        return KeyPair(pk, sk)
    }

    fun share(
        key: ByteArray,
        nonce: ByteArray,
        recipientPublicKey: ByteArray,
        senderPrivateKey: ByteArray,
    ): ByteArray {
        validateNonce(nonce)
        // The wrapped collection key is key material like any other: a
        // wrong-length value here would be sealed and shipped without complaint.
        validateKey(key)
        validateKey(recipientPublicKey)
        validateKey(senderPrivateKey)
        val ct = ByteArray(key.size + WireConstants.TAG_BYTES)
        val ok = sodium.cryptoBoxEasy(
            ct, key, key.size.toLong(), nonce, recipientPublicKey, senderPrivateKey,
        )
        if (!ok) throw CryptoError.InvalidInput("crypto_box encryption failed")
        return ct
    }

    /**
     * Throws unless the envelope really came from `senderPublicKey`. That is
     * the entire point of this class.
     */
    fun openShare(
        ciphertext: ByteArray,
        nonce: ByteArray,
        senderPublicKey: ByteArray,
        recipientPrivateKey: ByteArray,
    ): ByteArray {
        validateNonce(nonce)
        validateKey(senderPublicKey)
        validateKey(recipientPrivateKey)
        // <= , not < : same reason as KeyBox.open - a tag-only envelope would
        // otherwise authenticate and return an empty collection key. (Contrast
        // ContentStream.open, which keeps < because a 16-byte tag-only chunk is
        // the legitimate encoding of an empty file.)
        if (ciphertext.size <= WireConstants.TAG_BYTES) {
            throw CryptoError.InvalidInput("ciphertext carries no plaintext: must be longer than the authentication tag")
        }
        val pt = ByteArray(ciphertext.size - WireConstants.TAG_BYTES)
        val ok = sodium.cryptoBoxOpenEasy(
            pt, ciphertext, ciphertext.size.toLong(), nonce, senderPublicKey, recipientPrivateKey,
        )
        if (!ok) throw CryptoError.AuthenticationFailed
        return pt
    }

    private fun validateNonce(nonce: ByteArray) {
        if (nonce.size != WireConstants.NONCE_BYTES) {
            throw CryptoError.InvalidNonceLength(WireConstants.NONCE_BYTES, nonce.size)
        }
    }

    private fun validateKey(k: ByteArray) {
        if (k.size != WireConstants.KEY_BYTES) {
            throw CryptoError.InvalidKeyLength(WireConstants.KEY_BYTES, k.size)
        }
    }
}
