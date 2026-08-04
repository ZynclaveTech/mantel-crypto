package com.zynclave.familyalbum.cryptov2

/**
 * Errors thrown by the Protocol v2 crypto core.
 *
 * Every failure throws. Nothing signals failure by returning null or empty
 * bytes: the protocol this replaces had unauthenticated key wraps that failed
 * silently, and that silence is what let key substitution go unnoticed.
 */
sealed class CryptoError(message: String) : Exception(message) {
    class InvalidKeyLength(expected: Int, got: Int) :
        CryptoError("key must be $expected bytes, got $got")
    class InvalidNonceLength(expected: Int, got: Int) :
        CryptoError("nonce must be $expected bytes, got $got")
    class InvalidInput(detail: String) : CryptoError(detail)
    /**
     * Argon2id `memlimit`/`opslimit` were not an exact match for one of
     * [PasswordKdf.TIERS]. Per spec §5.3 these parameters come from an
     * UNAUTHENTICATED, server-controlled endpoint, so this is a possible
     * parameter-downgrade attempt, not an ordinary input error.
     *
     * Deliberately its own case rather than [InvalidInput]: spec §5.1 has the
     * client step down a tier ONLY on allocation failure, so a Phase 2 retry
     * loop will plausibly do `catch (e: CryptoError.InvalidInput) {
     * nextTier() }`. If this shared that type, the catch would treat a
     * detected downgrade exactly like "ran out of memory" and silently retry
     * with the next tier - quietly undoing the whitelist with entirely
     * reasonable-looking code. This type MUST NOT be caught by that retry;
     * only allocation failure should ever move to the next tier.
     */
    class UnapprovedKdfParameters(memlimit: Long, opslimit: Long) :
        CryptoError("Argon2id parameters not in the approved tier ladder: $memlimit/$opslimit")
    /** Wrong key, tampered ciphertext, or a forged sender. */
    object AuthenticationFailed : CryptoError("authentication failed")
    object EmptyStream : CryptoError("stream must contain at least one chunk")
}

/**
 * Wire-spec constants. Changing any of these breaks every already-encrypted
 * photo and every other implementation of the protocol.
 */
object WireConstants {
    /**
     * Production plaintext chunk size. Aligns with S3's 5 MiB minimum
     * multipart part size, so one encryption chunk maps to one S3 part.
     */
    const val CHUNK_SIZE = 8 * 1024 * 1024
    const val NONCE_PREFIX_BYTES = 19
    const val NONCE_BYTES = 24
    const val TAG_BYTES = 16
    const val KEY_BYTES = 32
    const val SALT_BYTES = 16
    const val FILE_ID_BYTES = 16

    /** crypto_kdf contexts. EXACTLY 8 bytes each - libsodium requires it. */
    const val AUTH_CONTEXT = "mantelAu"
    const val VARIANT_CONTEXT = "mantelFV"

    const val VARIANT_THUMB = 1
    const val VARIANT_PREVIEW = 2
    const val VARIANT_ORIGINAL = 3
}
