import Foundation
import Clibsodium

/// 60-digit safety number for out-of-band identity verification.
///
/// The server hands clients each other's identity public keys, so the server
/// can lie. Two members compare these digits out of band to confirm they hold
/// each other's real keys.
///
/// v1 displayed a 6-hex-character fingerprint - 24 bits. Grinding an X25519
/// keypair to match a chosen 24-bit target is about 16 million keygens, i.e.
/// seconds on a laptop, so the "verify this code" step was defeatable by
/// construction.
///
/// Modelled on Signal's safety-number scheme, with two documented deltas:
/// Signal re-appends the public key an extra time on its first hash iteration,
/// and Signal orders unconditionally by rendered digit strings where this
/// orders by raw public-key bytes, falling back to digit strings only when
/// the two keys are byte-identical (see `compute`). The digit encoding is
/// identical. Stated precisely because the threat model is published.
///
/// Uses Clibsodium because Sodium exposes no SHA-512.
public enum SafetyNumber {

    private static let iterations = 5200
    private static let version: UInt16 = 0

    public static func compute(publicKeyA: [UInt8], subA: String,
                               publicKeyB: [UInt8], subB: String) throws -> String {
        guard publicKeyA.count == MantelCryptoConstants.keyBytes else {
            throw CryptoError.invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: publicKeyA.count)
        }
        guard publicKeyB.count == MantelCryptoConstants.keyBytes else {
            throw CryptoError.invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: publicKeyB.count)
        }
        let a = try digits(for: publicKeyA, identifier: subA)
        let b = try digits(for: publicKeyB, identifier: subB)
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
        let precedes = publicKeyA == publicKeyB
            ? a <= b
            : lexicographicallyPrecedes(publicKeyA, publicKeyB)
        return precedes ? a + b : b + a
    }

    // MARK: - Implementation details (some internal for test visibility, see below)

    /// h1 = SHA512(version(2, big-endian) || pubkey || utf8(identifier))
    /// hi = SHA512(h(i-1) || pubkey)   for i = 2...5200
    /// then take the first 30 bytes.
    ///
    /// `throws` only to propagate a `sha512` failure - see that function's
    /// doc comment for why the module's stated contract requires this even
    /// though libsodium's SHA-512 does not fail in practice.
    private static func fingerprint(_ pubKey: [UInt8], _ identifier: String) throws -> [UInt8] {
        var seed = [UInt8]()
        seed.append(UInt8((version >> 8) & 0xff))
        seed.append(UInt8(version & 0xff))
        seed += pubKey
        seed += Array(identifier.utf8)

        var h = try sha512(seed)
        for _ in 1..<iterations {
            h = try sha512(h + pubKey)
        }
        return Array(h[0..<30])
    }

    /// 30 bytes -> six 5-byte groups -> each big-endian uint40 mod 100000,
    /// zero-padded to 5 digits.
    ///
    /// `internal`, not public: one party's own 30 digits verify nothing by
    /// themselves - only the combined 60 digits from `compute` are a
    /// verification artefact. `internal` keeps that footgun out of app code
    /// while still being visible to `@testable import`, so the fixture's
    /// per-party digits can be pinned directly.
    ///
    /// Validates `pubKey`'s length itself (matching Android's `digitsFor`,
    /// which calls `requireKey`) rather than relying on every caller to have
    /// checked first. `compute` already validates both keys before calling
    /// here, so this guard is currently unreachable from `compute`, but
    /// `digits(for:)` is visible to `@testable import` and must not silently
    /// hash the wrong number of bytes if a test - or a future caller - hands
    /// it a short key.
    static func digits(for pubKey: [UInt8], identifier: String) throws -> String {
        guard pubKey.count == MantelCryptoConstants.keyBytes else {
            throw CryptoError.invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: pubKey.count)
        }
        let fp = try fingerprint(pubKey, identifier)
        var out = ""
        for i in stride(from: 0, to: 30, by: 5) {
            var v: UInt64 = 0
            for j in 0..<5 { v = (v << 8) | UInt64(fp[i + j]) }
            out += String(format: "%05d", v % 100000)
        }
        return out
    }

    /// `throws` rather than discarding the return code: the module's stated
    /// posture is that every failure path throws, and libsodium's
    /// `crypto_hash_sha512` does return a nonzero code on failure even though
    /// SHA-512 has no observed failure mode in practice. Matches Android's
    /// `sha512`, which throws `CryptoError.InvalidInput` on the equivalent
    /// LazySodium call returning `false`.
    private static func sha512(_ input: [UInt8]) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 64)
        guard crypto_hash_sha512(&out, input, UInt64(input.count)) == 0 else {
            throw CryptoError.invalidInput("sha512 failed")
        }
        return out
    }

    private static func lexicographicallyPrecedes(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        for (x, y) in zip(a, b) where x != y { return x < y }
        // Unreachable from compute(): both keys are 32 bytes (validated above)
        // and the byte-identical case is handled by the caller's tie-break, so
        // a differing byte always exists and the loop always returns. This tail
        // is the line issue #88 named as the asymmetry bug - it is kept only to
        // keep the comparator total, and must not be read as the ordering rule
        // for equal keys.
        return a.count <= b.count
    }
}
