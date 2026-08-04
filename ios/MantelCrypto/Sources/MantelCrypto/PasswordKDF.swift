import Foundation
import Sodium

/// Argon2id password derivation and BLAKE2b subkey derivation.
///
/// This is the root of the key hierarchy: password -> KEK -> master key ->
/// everything else. `loginKey` is what gets sent to Cognito INSTEAD of the
/// password, so the server never sees it.
///
/// Consequence worth knowing: once the client sends loginKey, Cognito's
/// password policy is validating a 32-byte derived value and is therefore
/// meaningless. Password strength must be enforced client-side.
public enum PasswordKDF {

    private static let sodium = Sodium()

    /// Argon2id parameter tiers. The client steps down only on allocation
    /// failure, and the parameters actually used are stored server-side per
    /// user alongside the salt.
    public struct Tier: Equatable {
        public let name: String
        /// `Int`, not `Long` - Swift has no `Long` type. `Int` is 64-bit on
        /// every platform this package ships to (all are 64-bit targets), so
        /// this is the same width as Android's `Long memlimit`/`opslimit` on
        /// `PasswordKdf.Tier`, and the two ladders are numerically identical.
        /// The same `Int`/`Long` pairing holds for
        /// `CryptoError.unapprovedKDFParameters`, for the same reason - this
        /// is not the only site.
        public let memlimit: Int
        public let opslimit: Int
    }

    public static let tiers: [Tier] = [
        Tier(name: "default", memlimit: 256 * 1024 * 1024, opslimit: 4),
        Tier(name: "mid", memlimit: 128 * 1024 * 1024, opslimit: 6),
        Tier(name: "low", memlimit: 64 * 1024 * 1024, opslimit: 8),
    ]

    /// KEK = Argon2id(password, salt, params).
    ///
    /// `memlimit`/`opslimit` are NOT caller-chosen in production: per spec
    /// §5.3 the client fetches `{salt, params}` for the account from an
    /// UNAUTHENTICATED endpoint and derives KEK -> loginKey from whatever
    /// comes back. Spec §2.1 lists the Mantel operator (with full DynamoDB
    /// read/write) as a threat this design defends against, and §5.1/§11
    /// store `kdfParams` per user in exactly that table.
    ///
    /// So accepting arbitrary parameters is a password-recovery downgrade: an
    /// operator that serves `{mem: 8192, ops: 1}` gets the client to compute
    /// a weak KEK, derive a weak loginKey from it, and send that loginKey to
    /// operator-controlled Cognito. The login attempt fails, but the operator
    /// now holds a value one cheap Argon2id inversion away from the
    /// plaintext password - and the password yields the real KEK, the master
    /// key, and every photo.
    ///
    /// The `tiers` whitelist below is therefore load-bearing, not defensive
    /// decoration. It must stay an exact-pair match: the default tier has
    /// the LOWEST opslimit (4) and the HIGHEST memlimit, so no single
    /// inequality ("at least this much memory", "at least this many passes")
    /// expresses the ladder without admitting parameters that are not on it.
    public static func deriveKEK(password: String, salt: [UInt8],
                                 memlimit: Int, opslimit: Int) throws -> [UInt8] {
        guard salt.count == sodium.pwHash.SaltBytes else {
            throw CryptoError.invalidInput("salt must be \(sodium.pwHash.SaltBytes) bytes, got \(salt.count)")
        }
        guard tiers.contains(where: { $0.memlimit == memlimit && $0.opslimit == opslimit }) else {
            throw CryptoError.unapprovedKDFParameters(memlimit: memlimit, opslimit: opslimit)
        }
        guard let out = sodium.pwHash.hash(
            outputLength: MantelCryptoConstants.keyBytes,
            passwd: Array(password.utf8),
            salt: salt,
            opsLimit: opslimit,
            memLimit: memlimit,
            alg: .Argon2ID13
        ) else {
            // PINNED STRING (B2): `AccountKDF.deriveForEnrolment` in the app
            // target matches on "Argon2id failed" to distinguish an
            // allocation failure (safe to step down the ladder) from a
            // malformed-salt rejection (must not be retried). Nothing
            // enforces that coupling from this side - `ios/MantelCrypto` is
            // frozen this phase, so no new `CryptoError` case is being added
            // here, and this comment is the only thing tying the two
            // together. Rewording this message silently reopens the
            // downgrade this string currently guards against: on any
            // memory-constrained device, `deriveForEnrolment` would fail to
            // recognize the allocation failure and rethrow it immediately
            // instead of stepping down - i.e. enrolment would break on
            // exactly the low-memory devices the ladder exists to support.
            // See docs/superpowers/DEFERRED.md for the proper fix
            // (a distinct `CryptoError.allocationFailed` case).
            throw CryptoError.invalidInput("Argon2id failed - likely out of memory at this tier")
        }
        return out
    }

    /// loginKey = crypto_kdf_derive_from_key(KEK, 1, "mantelAu").
    public static func deriveLoginKey(kek: [UInt8]) throws -> [UInt8] {
        try deriveSubkey(key: kek, index: 1, context: MantelCryptoConstants.authContext)
    }

    /// fileKey -> per-variant content key, the ONLY key a caller may hand to
    /// `ContentStream.encrypt`.
    ///
    /// Spec §7.2 claims distinct per-variant subkeys make keystream reuse
    /// impossible "by construction". That is only true if every caller
    /// actually derives here instead of encrypting all three variants under
    /// the raw file key: identical keys plus a shared nonce prefix give
    /// `thumb XOR preview == plaintext XOR plaintext`, which is the v1
    /// defect verbatim.
    public static func deriveVariantKey(fileKey: [UInt8], variantId: UInt8) throws -> [UInt8] {
        guard (MantelCryptoConstants.variantThumb...MantelCryptoConstants.variantOriginal).contains(variantId) else {
            throw CryptoError.invalidInput(
                "variantId must be \(MantelCryptoConstants.variantThumb)...\(MantelCryptoConstants.variantOriginal), got \(variantId)")
        }
        return try deriveSubkey(key: fileKey, index: UInt64(variantId),
                                context: MantelCryptoConstants.variantContext)
    }

    /// Per-variant / per-purpose subkey derivation.
    public static func deriveSubkey(key: [UInt8], index: UInt64, context: String) throws -> [UInt8] {
        guard key.count == MantelCryptoConstants.keyBytes else {
            throw CryptoError.invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: key.count)
        }
        guard context.utf8.count == 8 else {
            throw CryptoError.invalidInput("kdf context must be exactly 8 bytes, got \(context.utf8.count)")
        }
        guard let out = sodium.keyDerivation.derive(
            secretKey: key, index: index,
            length: MantelCryptoConstants.keyBytes, context: context
        ) else {
            throw CryptoError.invalidInput("key derivation failed")
        }
        return out
    }
}
