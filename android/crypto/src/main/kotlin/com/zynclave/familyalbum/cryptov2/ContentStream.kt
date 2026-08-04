package com.zynclave.familyalbum.cryptov2

import com.goterl.lazysodium.LazySodium

/**
 * STREAM (Rogaway et al.) over XChaCha20-Poly1305.
 *
 * STREAM rather than libsodium's crypto_secretstream because secretstream
 * chains state between chunks, making decryption strictly sequential: seeking
 * to 40 minutes of video would mean decrypting the preceding 40 minutes. Here
 * every chunk decrypts independently, while the counter and final flag still
 * give reordering and truncation detection.
 *
 * Note for anyone comparing with the iOS core: iOS has to call libsodium
 * through its C interface because swift-sodium's AEAD wrapper generates its
 * own nonce. lazysodium accepts an explicit nonce, so no such workaround is
 * needed here.
 */
class ContentStream(private val sodium: LazySodium) {

    /** nonce = prefix(19) || counter(4, big-endian) || finalFlag(1) */
    fun buildNonce(prefix: ByteArray, counter: Long, isFinal: Boolean): ByteArray {
        if (prefix.size != WireConstants.NONCE_PREFIX_BYTES) {
            throw CryptoError.InvalidNonceLength(WireConstants.NONCE_PREFIX_BYTES, prefix.size)
        }
        if (counter < 0 || counter > 0xFFFFFFFFL) {
            throw CryptoError.InvalidInput("counter out of range: $counter")
        }
        val n = ByteArray(WireConstants.NONCE_BYTES)
        prefix.copyInto(n, 0)
        n[19] = ((counter shr 24) and 0xFF).toByte()
        n[20] = ((counter shr 16) and 0xFF).toByte()
        n[21] = ((counter shr 8) and 0xFF).toByte()
        n[22] = (counter and 0xFF).toByte()
        n[23] = if (isFinal) 1 else 0
        return n
    }

    /**
     * aad = fileId(16) || variantId(1). Binds each chunk to its file AND its
     * variant, so a chunk cannot be spliced in from another file or another
     * variant of the same file.
     */
    fun buildAad(fileId: ByteArray, variantId: Int): ByteArray {
        if (fileId.size != WireConstants.FILE_ID_BYTES) {
            throw CryptoError.InvalidInput("fileId must be ${WireConstants.FILE_ID_BYTES} bytes, got ${fileId.size}")
        }
        if (variantId !in WireConstants.VARIANT_THUMB..WireConstants.VARIANT_ORIGINAL) {
            throw CryptoError.InvalidInput("variantId must be 1..3, got $variantId")
        }
        return fileId + byteArrayOf(variantId.toByte())
    }

    /**
     * Encrypt one variant of one file.
     *
     * `key` MUST be `PasswordKdf.deriveVariantKey(fileKey, variantId)`. It MUST
     * NOT be the raw file key. `noncePrefix` MUST be 19 freshly random bytes
     * generated per (file, variant) and MUST NOT be shared with any other
     * variant of the same file.
     *
     * Reusing either across variants is a plaintext-recovering two-time pad:
     * same key + same prefix means the same keystream, so
     * `thumb XOR preview` cancels the keystream and leaks
     * `plaintext XOR plaintext`. AEAD authenticity does nothing about this -
     * confidentiality is already gone. This is the v1 defect this rewrite
     * exists to remove, and it is prevented here only by caller discipline:
     * nothing in this signature can tell a variant subkey from a file key.
     *
     * The same applies to RE-ENCRYPTION, not just to sibling variants. Spec §11
     * stores `noncePrefix{thumb,preview,original}` per photo, so a Phase 2
     * "re-upload after edit" path that reads the stored prefix back and
     * re-encrypts with an unchanged file key produces the identical keystream
     * over new plaintext - the same two-time pad by another route. Re-encrypting
     * means a fresh prefix (and, better, a fresh file key), never the stored one.
     */
    fun encrypt(
        plaintext: ByteArray,
        key: ByteArray,
        noncePrefix: ByteArray,
        fileId: ByteArray,
        variantId: Int,
        chunkSize: Int = WireConstants.CHUNK_SIZE,
    ): List<ByteArray> {
        validateKey(key)
        if (chunkSize <= 0) throw CryptoError.InvalidInput("chunkSize must be positive")

        // Zero-length plaintext still yields ONE authenticated chunk, so
        // decryption has something to verify rather than accepting nothing.
        val total = maxOf(1, ((plaintext.size.toLong() + chunkSize - 1) / chunkSize).toInt())
        return (0 until total).map { i ->
            val lo = i * chunkSize
            // Widened to Long: at the production 8 MiB chunk size, `lo +
            // chunkSize` overflows Int from i = 255 on, minOf then picks the
            // negative, and the final chunk is silently emitted empty - losing
            // up to 8 MB of plaintext with no exception on either side.
            val hi = minOf(lo.toLong() + chunkSize, plaintext.size.toLong()).toInt()
            val slice = if (lo < hi) plaintext.copyOfRange(lo, hi) else ByteArray(0)
            encryptChunk(slice, i.toLong(), i == total - 1, key, noncePrefix, fileId, variantId)
        }
    }

    /**
     * Encrypt one chunk in isolation - the streaming counterpart to
     * [decryptChunk], and what lets a caller encrypt a multi-gigabyte video
     * without holding the whole thing (or even a whole variant) in memory at
     * once. [encrypt] is now just this, called in a loop.
     *
     * `key` MUST be `PasswordKdf.deriveVariantKey(fileKey, variantId)`, never
     * the raw file key, and `noncePrefix` MUST be fresh per (file, variant).
     * See [encrypt]'s doc comment for why: reusing either is a
     * plaintext-recovering two-time pad, and nothing in this signature can
     * tell a variant subkey from a file key - that discipline is entirely on
     * the caller.
     *
     * Calling this directly also moves two guarantees [encrypt] used to give
     * you onto the caller:
     *
     * - Final-flag discipline: exactly one chunk - the last one - must be
     *   encrypted with `isFinal = true`. Getting this wrong produces a stream
     *   that [decrypt] will reject outright, which is the safe direction to
     *   fail in, but it will not encrypt to anything [decrypt] accepts.
     * - Truncation detection: it lives entirely in [decrypt]'s
     *   position-derived `isFinal` flag on the read side. A caller that
     *   assembles chunks itself (e.g. uploading each chunk as an S3 multipart
     *   part) gets per-chunk authenticity from this function, but NOT
     *   stream-level truncation detection unless it also independently
     *   records and checks the chunk count. [decryptChunk]'s doc comment
     *   carries the mirror of this caveat on the read side.
     */
    fun encryptChunk(
        plaintext: ByteArray,
        index: Long,
        isFinal: Boolean,
        key: ByteArray,
        noncePrefix: ByteArray,
        fileId: ByteArray,
        variantId: Int,
    ): ByteArray {
        validateKey(key)
        return seal(plaintext, buildAad(fileId, variantId), buildNonce(noncePrefix, index, isFinal), key)
    }

    fun decrypt(
        chunks: List<ByteArray>,
        key: ByteArray,
        noncePrefix: ByteArray,
        fileId: ByteArray,
        variantId: Int,
    ): ByteArray {
        validateKey(key)
        if (chunks.isEmpty()) throw CryptoError.EmptyStream
        val out = java.io.ByteArrayOutputStream()
        chunks.forEachIndexed { i, chunk ->
            out.write(
                decryptChunk(
                    chunk, i.toLong(), i == chunks.size - 1,
                    key, noncePrefix, fileId, variantId,
                )
            )
        }
        return out.toByteArray()
    }

    /**
     * Decrypt one chunk in isolation - this is what makes video seeking work.
     *
     * Truncation detection lives entirely in [decrypt]'s position-derived
     * `isFinal` flag: a random-access/seeking caller that only ever invokes
     * this with `isFinal = false` gets chunk-level authenticity but NOT
     * truncation detection for the stream as a whole.
     */
    fun decryptChunk(
        chunk: ByteArray,
        index: Long,
        isFinal: Boolean,
        key: ByteArray,
        noncePrefix: ByteArray,
        fileId: ByteArray,
        variantId: Int,
    ): ByteArray {
        validateKey(key)
        return open(chunk, buildAad(fileId, variantId), buildNonce(noncePrefix, index, isFinal), key)
    }

    private fun validateKey(key: ByteArray) {
        if (key.size != WireConstants.KEY_BYTES) {
            throw CryptoError.InvalidKeyLength(WireConstants.KEY_BYTES, key.size)
        }
    }

    // internal, not private: every production path reaches this nonce via
    // buildNonce (which itself always emits WireConstants.NONCE_BYTES), so
    // there is no way to drive a wrong-sized nonce here through the public
    // API - the assertion below can only be exercised directly, from
    // ContentStreamTest in this module.
    internal fun seal(message: ByteArray, aad: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        // Every path here reaches this nonce via buildNonce, which enforces
        // the 19-byte prefix and appends exactly 5 fixed bytes - so today
        // this can only ever be 24 bytes. But that is an inference about all
        // current callers, not something this function enforces on its own,
        // and this is the last remaining spot that took a nonce on trust
        // (the analogous check for key arguments already exists everywhere
        // else). Asserting here means buildNonce is the only thing that has
        // to be right.
        if (nonce.size != WireConstants.NONCE_BYTES) {
            throw CryptoError.InvalidNonceLength(WireConstants.NONCE_BYTES, nonce.size)
        }
        val ct = ByteArray(message.size + WireConstants.TAG_BYTES)
        val ctLen = LongArray(1)
        val ok = sodium.cryptoAeadXChaCha20Poly1305IetfEncrypt(
            ct, ctLen, message, message.size.toLong(), aad, aad.size.toLong(), null, nonce, key,
        )
        if (!ok) throw CryptoError.InvalidInput("AEAD encrypt failed")
        return ct.copyOf(ctLen[0].toInt())
    }

    // internal, not private: see seal()'s matching comment above.
    internal fun open(ciphertext: ByteArray, aad: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        // See seal()'s matching comment: buildNonce is the only thing that
        // has to be right for this to always be NONCE_BYTES, and this
        // asserts that instead of merely inferring it.
        if (nonce.size != WireConstants.NONCE_BYTES) {
            throw CryptoError.InvalidNonceLength(WireConstants.NONCE_BYTES, nonce.size)
        }
        if (ciphertext.size < WireConstants.TAG_BYTES) {
            throw CryptoError.InvalidInput("chunk shorter than the authentication tag")
        }
        val pt = ByteArray(ciphertext.size - WireConstants.TAG_BYTES)
        val ptLen = LongArray(1)
        // Failure covers every rejection we care about: wrong counter
        // (reordering), wrong final flag (truncation), wrong fileId or
        // variantId (splicing), and tampered bytes.
        val ok = sodium.cryptoAeadXChaCha20Poly1305IetfDecrypt(
            pt, ptLen, null, ciphertext, ciphertext.size.toLong(), aad, aad.size.toLong(), nonce, key,
        )
        if (!ok) throw CryptoError.AuthenticationFailed
        return pt.copyOf(ptLen[0].toInt())
    }
}
