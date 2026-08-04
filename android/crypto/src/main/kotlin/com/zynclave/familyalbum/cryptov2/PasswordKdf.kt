package com.zynclave.familyalbum.cryptov2

import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.interfaces.PwHash
import com.sun.jna.NativeLong

/**
 * Argon2id password derivation and BLAKE2b subkey derivation.
 *
 * Root of the key hierarchy: password -> KEK -> master key -> everything else.
 * `loginKey` is what gets sent to Cognito INSTEAD of the password, so the
 * server never sees it.
 *
 * Consequence: once the client sends loginKey, Cognito's password policy is
 * validating a 32-byte derived value and is therefore meaningless. Password
 * strength has to be enforced client-side.
 */
class PasswordKdf(private val sodium: LazySodium) {

    data class Tier(val name: String, val memlimit: Long, val opslimit: Long)

    companion object {
        /** Spec fallback ladder. The client steps down only on allocation failure. */
        val TIERS = listOf(
            Tier("default", 256L * 1024 * 1024, 4),
            Tier("mid", 128L * 1024 * 1024, 6),
            Tier("low", 64L * 1024 * 1024, 8),
        )
    }

    /**
     * KEK = Argon2id(password, salt, params).
     *
     * `memlimit`/`opslimit` are NOT caller-chosen in production: per spec §5.3
     * the client fetches `{salt, params}` for the account from an
     * UNAUTHENTICATED endpoint and derives KEK -> loginKey from whatever comes
     * back. Spec §2.1 lists the Mantel operator (with full DynamoDB read/write)
     * as a threat this design defends against, and §5.1/§11 store `kdfParams`
     * per user in exactly that table.
     *
     * So accepting arbitrary parameters is a password-recovery downgrade: an
     * operator that serves `{mem: 8192, ops: 1}` gets the client to compute a
     * weak KEK, derive a weak loginKey from it, and send that loginKey to
     * operator-controlled Cognito. The login attempt fails, but the operator
     * now holds a value one cheap Argon2id inversion away from the plaintext
     * password - and the password yields the real KEK, the master key, and
     * every photo.
     *
     * The [TIERS] whitelist below is therefore load-bearing, not defensive
     * decoration. It must stay an exact-pair match: the default tier has the
     * LOWEST opslimit (4) and the HIGHEST memlimit, so no single inequality
     * ("at least this much memory", "at least this many passes") expresses the
     * ladder without admitting parameters that are not on it.
     *
     * Rejection here throws [CryptoError.UnapprovedKdfParameters], a type
     * distinct from [CryptoError.InvalidInput]. Spec §5.1 has the client step
     * down a tier only on allocation failure, and allocation failure below
     * also throws [CryptoError.InvalidInput]. If the downgrade rejection
     * shared that type, the obvious Phase 2 retry loop -
     * `catch (e: CryptoError.InvalidInput) { nextTier() }` - would treat a
     * detected downgrade attempt as "try the next tier" and quietly retry
     * with operator-supplied weak parameters, neutralising this whole check.
     */
    fun deriveKek(password: String, salt: ByteArray, memlimit: Long, opslimit: Long): ByteArray {
        if (salt.size != WireConstants.SALT_BYTES) {
            throw CryptoError.InvalidInput("salt must be ${WireConstants.SALT_BYTES} bytes, got ${salt.size}")
        }
        if (TIERS.none { it.memlimit == memlimit && it.opslimit == opslimit }) {
            throw CryptoError.UnapprovedKdfParameters(memlimit, opslimit)
        }
        val out = ByteArray(WireConstants.KEY_BYTES)
        val pw = password.toByteArray(Charsets.UTF_8)
        // memLimit is a JNA NativeLong, not Int or Long - passing a plain
        // number does not compile.
        val ok = sodium.cryptoPwHash(
            out, out.size, pw, pw.size, salt,
            opslimit, NativeLong(memlimit), PwHash.Alg.PWHASH_ALG_ARGON2ID13,
        )
        if (!ok) throw CryptoError.InvalidInput("Argon2id failed - likely out of memory at this tier")
        return out
    }

    /** loginKey = crypto_kdf_derive_from_key(KEK, 1, "mantelAu"). */
    fun deriveLoginKey(kek: ByteArray): ByteArray =
        deriveSubkey(kek, 1, WireConstants.AUTH_CONTEXT)

    /**
     * fileKey -> per-variant content key, the ONLY key a caller may hand to
     * [ContentStream.encrypt].
     *
     * Spec §7.2 claims distinct per-variant subkeys make keystream reuse
     * impossible "by construction". That is only true if every caller actually
     * derives here instead of encrypting all three variants under the raw file
     * key: identical keys plus a shared nonce prefix give
     * `thumb XOR preview == plaintext XOR plaintext`, which is the v1 defect
     * verbatim.
     */
    fun deriveVariantKey(fileKey: ByteArray, variantId: Int): ByteArray {
        if (variantId !in WireConstants.VARIANT_THUMB..WireConstants.VARIANT_ORIGINAL) {
            throw CryptoError.InvalidInput(
                "variantId must be ${WireConstants.VARIANT_THUMB}..${WireConstants.VARIANT_ORIGINAL}, got $variantId",
            )
        }
        return deriveSubkey(fileKey, variantId.toLong(), WireConstants.VARIANT_CONTEXT)
    }

    /** Per-variant / per-purpose subkey derivation. */
    fun deriveSubkey(key: ByteArray, index: Long, context: String): ByteArray {
        if (key.size != WireConstants.KEY_BYTES) {
            throw CryptoError.InvalidKeyLength(WireConstants.KEY_BYTES, key.size)
        }
        val ctx = context.toByteArray(Charsets.UTF_8)
        if (ctx.size != 8) {
            throw CryptoError.InvalidInput("kdf context must be exactly 8 bytes, got ${ctx.size}")
        }
        val out = ByteArray(WireConstants.KEY_BYTES)
        // The context is a ByteArray here, not a String.
        val rc = sodium.cryptoKdfDeriveFromKey(out, out.size, index, ctx, key)
        if (rc != 0) throw CryptoError.InvalidInput("key derivation failed (rc=$rc)")
        return out
    }
}
