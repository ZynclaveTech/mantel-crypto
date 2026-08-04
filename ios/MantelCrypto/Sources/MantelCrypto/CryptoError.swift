import Foundation

/// Errors thrown by the Protocol v2 crypto core.
///
/// Every failure is thrown, never signalled by returning nil or empty data.
/// The protocol this replaces had unauthenticated key wraps that failed
/// silently; loud failure is a deliberate property here.
public enum CryptoError: Error, Equatable {
    case invalidKeyLength(expected: Int, got: Int)
    case invalidNonceLength(expected: Int, got: Int)
    case invalidInput(String)
    /// Argon2id `memlimit`/`opslimit` were not an exact match for one of
    /// `PasswordKDF.tiers`. Per spec §5.3 these parameters come from an
    /// UNAUTHENTICATED, server-controlled endpoint, so this is a possible
    /// parameter-downgrade attempt, not an ordinary input error.
    ///
    /// Deliberately its own case rather than `.invalidInput`: spec §5.1 has
    /// the client step down a tier ONLY on allocation failure, and allocation
    /// failure also throws `.invalidInput`. If this case shared that one, a
    /// Phase 2 retry loop written as `catch .invalidInput { nextTier() }`
    /// would treat a detected downgrade exactly like "ran out of memory" and
    /// silently retry with the operator-supplied weak parameters - quietly
    /// undoing the whitelist with entirely reasonable-looking code. This case
    /// MUST NOT be caught by that retry; only allocation failure should ever
    /// move to the next tier.
    case unapprovedKDFParameters(memlimit: Int, opslimit: Int)
    /// Authentication failed: wrong key, tampered ciphertext, or a forged sender.
    case authenticationFailed
    case emptyStream
}

/// Wire-spec constants. Changing any of these breaks every already-encrypted
/// photo and every other implementation of the protocol.
public enum MantelCryptoConstants {
    /// Production plaintext chunk size. Aligns with S3's 5 MiB minimum
    /// multipart part size, so one encryption chunk maps to one S3 part.
    public static let chunkSize = 8 * 1024 * 1024
    public static let noncePrefixBytes = 19
    public static let nonceBytes = 24
    public static let tagBytes = 16
    public static let keyBytes = 32
    public static let secretBoxNonceBytes = 24

    /// crypto_kdf contexts. EXACTLY 8 bytes each - libsodium requires it.
    public static let authContext = "mantelAu"
    public static let variantContext = "mantelFV"

    /// Variant ids used both as kdf subkey indices and in the AEAD AAD.
    public static let variantThumb: UInt8 = 1
    public static let variantPreview: UInt8 = 2
    public static let variantOriginal: UInt8 = 3
}
