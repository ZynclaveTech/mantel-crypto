package com.zynclave.familyalbum.cryptov2

import com.goterl.lazysodium.LazySodium
import java.math.BigInteger

/**
 * 60-digit safety number for out-of-band identity verification.
 *
 * The server hands clients each other's identity public keys, so the server
 * can lie. Two members compare these digits out of band to confirm they hold
 * each other's real keys.
 *
 * v1 displayed a 6-hex-character fingerprint - 24 bits. Grinding an X25519
 * keypair to match a chosen 24-bit target is about 16 million keygens, i.e.
 * seconds on a laptop, so the "verify this code" step was defeatable by
 * construction.
 *
 * Modelled on Signal's safety-number scheme, with two documented deltas:
 * Signal re-appends the public key an extra time on its first hash iteration,
 * and Signal orders unconditionally by rendered digit strings where this
 * orders by raw public-key bytes, falling back to digit strings only when the
 * two keys are byte-identical (see [compute]). The digit encoding is
 * identical. Stated precisely because the threat model is published.
 */
class SafetyNumber(private val sodium: LazySodium) {

    private companion object {
        const val ITERATIONS = 5200
        const val VERSION = 0
    }

    fun compute(publicKeyA: ByteArray, subA: String, publicKeyB: ByteArray, subB: String): String {
        requireKey(publicKeyA)
        requireKey(publicKeyB)
        val a = digitsFor(publicKeyA, subA)
        val b = digitsFor(publicKeyB, subB)
        // Order by public key so both sides produce the same 60 digits,
        // unconditionally, no matter which party is "local".
        //
        // Distinct keys are still ordered by raw bytes rather than by the
        // rendered digit strings: every safety number already shown to a
        // user, and the fixture at tools/vectors/vectors.json, was computed
        // with byte ordering, so switching to digit-string ordering would
        // silently change numbers users have already verified. Byte-identical
        // keys have no byte order to speak of (two family members sharing one
        // identity key is itself an anomaly, but must still produce one consistent
        // number on both devices), so fall back to ordering by the rendered digit
        // strings there. Sorting two strings ascending is symmetric
        // regardless of which one is passed as "local", so this stays
        // order-independent even when the identifiers - and therefore the
        // digit strings themselves - are also identical.
        val precedes = if (publicKeyA.contentEquals(publicKeyB)) {
            a <= b
        } else {
            lexicographicallyPrecedes(publicKeyA, publicKeyB)
        }
        return if (precedes) a + b else b + a
    }

    /**
     * h1 = SHA512(version(2, big-endian) || pubkey || utf8(identifier))
     * hi = SHA512(h(i-1) || pubkey)   for i = 2..5200
     * then first 30 bytes -> six 5-byte groups -> uint40 mod 100000, 5 digits each.
     *
     * `internal`, not public: one party's own 30 digits verify nothing by
     * themselves - only the combined 60 digits from [compute] are a
     * verification artefact. `internal` keeps that footgun out of app code
     * while still being visible to the test source set (a friend
     * compilation), so the fixture's per-party digits can be pinned directly.
     */
    internal fun digitsFor(publicKey: ByteArray, identifier: String): String {
        requireKey(publicKey)
        val id = identifier.toByteArray(Charsets.UTF_8)
        val seed = ByteArray(2 + publicKey.size + id.size)
        seed[0] = ((VERSION shr 8) and 0xFF).toByte()
        seed[1] = (VERSION and 0xFF).toByte()
        publicKey.copyInto(seed, 2)
        id.copyInto(seed, 2 + publicKey.size)

        var h = sha512(seed)
        repeat(ITERATIONS - 1) { h = sha512(h + publicKey) }
        val fp = h.copyOf(30)

        val sb = StringBuilder(30)
        for (i in 0 until 30 step 5) {
            var v = BigInteger.ZERO
            for (j in 0 until 5) {
                v = v.shiftLeft(8).or(BigInteger.valueOf((fp[i + j].toInt() and 0xFF).toLong()))
            }
            sb.append(v.mod(BigInteger.valueOf(100000)).toString().padStart(5, '0'))
        }
        return sb.toString()
    }

    private fun sha512(input: ByteArray): ByteArray {
        val out = ByteArray(64)
        if (!sodium.cryptoHashSha512(out, input, input.size.toLong())) {
            throw CryptoError.InvalidInput("sha512 failed")
        }
        return out
    }

    private fun requireKey(k: ByteArray) {
        if (k.size != WireConstants.KEY_BYTES) {
            throw CryptoError.InvalidKeyLength(WireConstants.KEY_BYTES, k.size)
        }
    }

    private fun lexicographicallyPrecedes(a: ByteArray, b: ByteArray): Boolean {
        for (i in 0 until minOf(a.size, b.size)) {
            val x = a[i].toInt() and 0xFF
            val y = b[i].toInt() and 0xFF
            if (x != y) return x < y
        }
        // Unreachable from compute(): both keys are 32 bytes (requireKey) and
        // the byte-identical case is handled by the caller's tie-break, so a
        // differing byte always exists and the loop always returns. This tail
        // is the line issue #88 named as the asymmetry bug - it is kept only
        // to keep the comparator total, and must not be read as the ordering
        // rule for equal keys.
        return a.size <= b.size
    }
}
