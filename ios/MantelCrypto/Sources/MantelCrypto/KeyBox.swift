import Foundation
import Sodium

/// XSalsa20-Poly1305 symmetric wrap (crypto_secretbox).
///
/// One primitive, six uses in the key hierarchy - and beyond it. Spec §7.4
/// also routes the photo metadata blob, the album name, and the reaction
/// emoji through this class, so "wraps key material" is not a safe
/// assumption for any caller:
///   master key    under the KEK
///   master key    under the recovery key   (independent second unlock path)
///   identity priv under the master key
///   collection key under the master key    (album owner's own copy)
///   file key      under the collection key
///   metadata blob under the file key
public enum KeyBox {

    private static let sodium = Sodium()

    public static func seal(plaintext: [UInt8], nonce: [UInt8], wrappingKey: [UInt8]) throws -> [UInt8] {
        try validate(nonce: nonce, key: wrappingKey)
        // Restores the invariant that anything seal produces, open accepts:
        // open() below rejects a tag-only ciphertext, so an empty plaintext
        // here must be rejected too, not sealed. The alternative is a seal()
        // that reports success while producing a ciphertext no client can
        // ever open again - already persisted, undecryptable at rest. An
        // empty album name or reaction emoji (spec §7.4) is an ordinary
        // thing for a UI to produce, so this is reachable in practice, not
        // just in theory.
        guard !plaintext.isEmpty else {
            throw CryptoError.invalidInput("nothing to wrap: plaintext is empty")
        }
        guard let ct = sodium.secretBox.seal(message: plaintext, secretKey: wrappingKey, nonce: nonce) else {
            throw CryptoError.invalidInput("secretbox seal failed")
        }
        return ct
    }

    /// Throws `.authenticationFailed` on a wrong key, a tampered ciphertext, or
    /// a tampered nonce. Never returns nil - the protocol this replaces failed
    /// silently, and that is what let key substitution go unnoticed.
    public static func open(ciphertext: [UInt8], nonce: [UInt8], wrappingKey: [UInt8]) throws -> [UInt8] {
        try validate(nonce: nonce, key: wrappingKey)
        // Strictly greater than, not >=: a bare tagBytes-length ciphertext
        // authenticates fine and would return [] - an EMPTY MASTER KEY (or
        // metadata blob, or album name) handed back as success. This is
        // deliberately tighter than ContentStream.open's `>= tagBytes`: a
        // 16-byte tag-only STREAM chunk is the legitimate encoding of an
        // empty file (decryption needs something to verify), but nothing
        // this class wraps is ever legitimately empty - seal() above now
        // enforces that on the way in, so a zero-length unwrap here can only
        // mean a malformed input, never a real result.
        guard ciphertext.count > MantelCryptoConstants.tagBytes else {
            throw CryptoError.invalidInput("ciphertext carries no plaintext: must be longer than the authentication tag")
        }
        guard let pt = sodium.secretBox.open(
            authenticatedCipherText: ciphertext, secretKey: wrappingKey, nonce: nonce
        ) else {
            throw CryptoError.authenticationFailed
        }
        return pt
    }

    private static func validate(nonce: [UInt8], key: [UInt8]) throws {
        guard nonce.count == MantelCryptoConstants.secretBoxNonceBytes else {
            throw CryptoError.invalidNonceLength(
                expected: MantelCryptoConstants.secretBoxNonceBytes, got: nonce.count)
        }
        guard key.count == MantelCryptoConstants.keyBytes else {
            throw CryptoError.invalidKeyLength(
                expected: MantelCryptoConstants.keyBytes, got: key.count)
        }
    }
}
