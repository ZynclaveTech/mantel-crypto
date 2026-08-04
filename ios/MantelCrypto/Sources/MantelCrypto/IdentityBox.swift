import Foundation
import Sodium

/// X25519 + XSalsa20-Poly1305 AUTHENTICATED sharing (crypto_box).
///
/// `crypto_box_seal` is deliberately NOT used anywhere in this protocol.
/// Anonymous sealing authenticates nothing about the sender, which is exactly
/// the v1 defect: collection keys arrived in envelopes sealed with an ephemeral
/// key, so the recipient could not tell who produced them, and any member could
/// overwrite anyone's content key.
///
/// With crypto_box, `openShare` succeeds only if the envelope was produced by
/// the claimed sender's identity key. Forging a key delivery is impossible
/// rather than merely disallowed.
public enum IdentityBox {

    private static let sodium = Sodium()

    /// Deterministic X25519 keypair from a 32-byte seed.
    public static func keypair(seed: [UInt8]) throws -> (publicKey: [UInt8], privateKey: [UInt8]) {
        guard seed.count == MantelCryptoConstants.keyBytes else {
            throw CryptoError.invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: seed.count)
        }
        guard let kp = sodium.box.keyPair(seed: seed) else {
            throw CryptoError.invalidInput("box keypair derivation failed")
        }
        return (publicKey: kp.publicKey, privateKey: kp.secretKey)
    }

    public static func share(key: [UInt8], nonce: [UInt8],
                             recipientPublicKey: [UInt8], senderPrivateKey: [UInt8]) throws -> [UInt8] {
        try validate(nonce: nonce)
        // The wrapped collection key is protocol data like any other: a
        // wrong-length value here would be sealed and shipped without
        // complaint. swift-sodium catches wrong-length recipient/sender keys
        // and returns nil, but that would surface as the generic "box seal
        // failed" below rather than naming which argument was malformed.
        try validateKey(key)
        try validateKey(recipientPublicKey)
        try validateKey(senderPrivateKey)
        guard let ct = sodium.box.seal(
            message: key,
            recipientPublicKey: recipientPublicKey,
            senderSecretKey: senderPrivateKey,
            nonce: nonce
        ) else {
            throw CryptoError.invalidInput("box seal failed")
        }
        return ct
    }

    /// Throws `.authenticationFailed` unless the envelope really came from
    /// `senderPublicKey`. That is the entire point of this module.
    ///
    /// Key-length validation runs BEFORE the open call so a malformed key
    /// (a serialisation bug, a truncated keychain read, a bad migration)
    /// throws `.invalidKeyLength` rather than `.authenticationFailed`.
    /// swift-sodium returns nil for a wrong-length key exactly as it does
    /// for a failed MAC, so without this guard the two are indistinguishable
    /// - and in a protocol whose entire security story is "openShare failing
    /// means someone forged this envelope", that is the wrong signal on the
    /// wrong channel.
    public static func openShare(ciphertext: [UInt8], nonce: [UInt8],
                                 senderPublicKey: [UInt8], recipientPrivateKey: [UInt8]) throws -> [UInt8] {
        try validate(nonce: nonce)
        try validateKey(senderPublicKey)
        try validateKey(recipientPrivateKey)
        // Strictly greater than, not >=: swift-sodium's box.open only
        // requires ciphertext.count >= MacBytes, so a bare 16-byte tag
        // authenticates and returns [] - an EMPTY COLLECTION KEY handed back
        // as success. Same shape as KeyBox.open, same reason: nothing this
        // method returns is ever legitimately empty (contrast
        // ContentStream.open, which keeps >=, because a 16-byte tag-only
        // STREAM chunk is the legitimate encoding of an empty file).
        guard ciphertext.count > MantelCryptoConstants.tagBytes else {
            throw CryptoError.invalidInput("ciphertext carries no plaintext: must be longer than the authentication tag")
        }
        guard let pt = sodium.box.open(
            authenticatedCipherText: ciphertext,
            senderPublicKey: senderPublicKey,
            recipientSecretKey: recipientPrivateKey,
            nonce: nonce
        ) else {
            throw CryptoError.authenticationFailed
        }
        return pt
    }

    private static func validate(nonce: [UInt8]) throws {
        guard nonce.count == sodium.box.NonceBytes else {
            throw CryptoError.invalidNonceLength(expected: sodium.box.NonceBytes, got: nonce.count)
        }
    }

    private static func validateKey(_ k: [UInt8]) throws {
        guard k.count == MantelCryptoConstants.keyBytes else {
            throw CryptoError.invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: k.count)
        }
    }
}
