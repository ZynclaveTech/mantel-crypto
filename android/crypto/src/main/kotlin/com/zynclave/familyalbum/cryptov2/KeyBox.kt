package com.zynclave.familyalbum.cryptov2

import com.goterl.lazysodium.LazySodium

/**
 * XSalsa20-Poly1305 symmetric wrap (crypto_secretbox).
 *
 * One primitive, six uses in the key hierarchy:
 *   master key    under the KEK
 *   master key    under the recovery key   (independent second unlock path)
 *   identity priv under the master key
 *   collection key under the master key    (album owner's own copy)
 *   file key      under the collection key
 *   metadata blob under the file key
 */
class KeyBox(private val sodium: LazySodium) {

    fun seal(plaintext: ByteArray, nonce: ByteArray, wrappingKey: ByteArray): ByteArray {
        validate(nonce, wrappingKey)
        // Restores the invariant that anything seal produces, open accepts:
        // open() rejects a tag-only ciphertext (see below), so an empty
        // plaintext here must be rejected too, not sealed. The alternative is
        // a seal() that reports success while producing a ciphertext no
        // client can ever open again - already persisted, undecryptable at
        // rest.
        if (plaintext.isEmpty()) {
            throw CryptoError.InvalidInput("nothing to wrap: plaintext is empty")
        }
        val ct = ByteArray(plaintext.size + WireConstants.TAG_BYTES)
        val ok = sodium.cryptoSecretBoxEasy(ct, plaintext, plaintext.size.toLong(), nonce, wrappingKey)
        if (!ok) throw CryptoError.InvalidInput("secretbox seal failed")
        return ct
    }

    /**
     * Throws on a wrong key, a tampered ciphertext, or a tampered nonce.
     * Never returns null - the protocol this replaces failed silently, and
     * that is what let key substitution go unnoticed.
     */
    fun open(ciphertext: ByteArray, nonce: ByteArray, wrappingKey: ByteArray): ByteArray {
        validate(nonce, wrappingKey)
        // <= , not < : a bare 16-byte tag authenticates fine and would return
        // ByteArray(0), i.e. an empty MASTER KEY handed back as success. This
        // class wraps key material, but also the photo metadata blob, the
        // album name, and the reaction emoji (spec §7.4) - an empty album
        // name is an ordinary thing for a UI to produce - so seal() rejects
        // an empty plaintext up front and a zero-length unwrap here is always
        // a malformed input, never a legitimate result.
        if (ciphertext.size <= WireConstants.TAG_BYTES) {
            throw CryptoError.InvalidInput("ciphertext carries no plaintext: must be longer than the authentication tag")
        }
        val pt = ByteArray(ciphertext.size - WireConstants.TAG_BYTES)
        val ok = sodium.cryptoSecretBoxOpenEasy(pt, ciphertext, ciphertext.size.toLong(), nonce, wrappingKey)
        if (!ok) throw CryptoError.AuthenticationFailed
        return pt
    }

    private fun validate(nonce: ByteArray, key: ByteArray) {
        if (nonce.size != WireConstants.NONCE_BYTES) {
            throw CryptoError.InvalidNonceLength(WireConstants.NONCE_BYTES, nonce.size)
        }
        if (key.size != WireConstants.KEY_BYTES) {
            throw CryptoError.InvalidKeyLength(WireConstants.KEY_BYTES, key.size)
        }
    }
}
