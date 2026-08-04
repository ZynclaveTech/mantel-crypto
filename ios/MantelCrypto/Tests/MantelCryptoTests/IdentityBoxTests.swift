import XCTest
import Sodium
@testable import MantelCrypto

final class IdentityBoxTests: XCTestCase {

    func testKeypairsMatchFixture() throws {
        let id = try Vectors.section("identity")
        for name in ["alice", "bob", "mallory"] {
            let party = id[name] as! [String: Any]
            let kp = try IdentityBox.keypair(seed: unhex(party["seed_hex"] as! String))
            XCTAssertEqual(hex(kp.publicKey), party["pub_hex"] as! String, "\(name) pub")
            XCTAssertEqual(hex(kp.privateKey), party["priv_hex"] as! String, "\(name) priv")
        }
    }

    func testShareAliceToBobMatchesFixture() throws {
        let id = try Vectors.section("identity")
        let alice = id["alice"] as! [String: Any]
        let bob = id["bob"] as! [String: Any]
        let share = id["share_alice_to_bob"] as! [String: Any]

        let ct = try IdentityBox.share(
            key: unhex(share["plaintext_hex"] as! String),
            nonce: unhex(share["nonce_hex"] as! String),
            recipientPublicKey: unhex(bob["pub_hex"] as! String),
            senderPrivateKey: unhex(alice["priv_hex"] as! String))
        XCTAssertEqual(hex(ct), share["ciphertext_hex"] as! String)

        let back = try IdentityBox.openShare(
            ciphertext: ct,
            nonce: unhex(share["nonce_hex"] as! String),
            senderPublicKey: unhex(alice["pub_hex"] as! String),
            recipientPrivateKey: unhex(bob["priv_hex"] as! String))
        XCTAssertEqual(hex(back), share["plaintext_hex"] as! String)
    }

    /// THE test this whole protocol rewrite exists for.
    ///
    /// Mallory is not a family member. She seals a collection key for Bob while
    /// claiming to be Alice. Opening it against Alice's public key MUST fail.
    /// Under v1 - which used an ephemeral, unauthenticated sender key - it
    /// would have succeeded, and any member could substitute anyone's content
    /// key.
    func testForgedShareClaimingAliceIsRejected() throws {
        let id = try Vectors.section("identity")
        let alice = id["alice"] as! [String: Any]
        let bob = id["bob"] as! [String: Any]
        let forged = id["forged_by_mallory_claiming_alice"] as! [String: Any]

        XCTAssertThrowsError(try IdentityBox.openShare(
            ciphertext: unhex(forged["ciphertext_hex"] as! String),
            nonce: unhex(forged["nonce_hex"] as! String),
            senderPublicKey: unhex(alice["pub_hex"] as! String),
            recipientPrivateKey: unhex(bob["priv_hex"] as! String))) { error in
            XCTAssertEqual(error as? CryptoError, .authenticationFailed)
        }
    }

    func testWrongRecipientIsRejected() throws {
        let id = try Vectors.section("identity")
        let alice = id["alice"] as! [String: Any]
        let mallory = id["mallory"] as! [String: Any]
        let share = id["share_alice_to_bob"] as! [String: Any]

        XCTAssertThrowsError(try IdentityBox.openShare(
            ciphertext: unhex(share["ciphertext_hex"] as! String),
            nonce: unhex(share["nonce_hex"] as! String),
            senderPublicKey: unhex(alice["pub_hex"] as! String),
            recipientPrivateKey: unhex(mallory["priv_hex"] as! String))) { error in
            // Under #86's own thesis - pin the failure MODE so a length
            // rejection cannot masquerade as MAC failure - this must be
            // .authenticationFailed, like its forgery-test sibling above.
            XCTAssertEqual(error as? CryptoError, .authenticationFailed)
        }
    }

    func testRejectsWrongSeedLength() {
        XCTAssertThrowsError(try IdentityBox.keypair(seed: [UInt8](repeating: 0, count: 31)))
    }

    /// share/openShare validated only the nonce - key, recipientPublicKey,
    /// senderPrivateKey, senderPublicKey and recipientPrivateKey were all
    /// unchecked. swift-sodium fails closed on a wrong-length key (returns
    /// nil), so this is not the memory-safety gap ContentStream has, but a
    /// malformed key must be reported as exactly that - not folded into
    /// .authenticationFailed, which this protocol's UI will read as "your
    /// family member is being impersonated".
    func testRejectsWrongLengthKeyMaterial() throws {
        let id = try Vectors.section("identity")
        let alice = id["alice"] as! [String: Any]
        let bob = id["bob"] as! [String: Any]
        let share = id["share_alice_to_bob"] as! [String: Any]
        let plaintext = unhex(share["plaintext_hex"] as! String)
        let validNonce = unhex(share["nonce_hex"] as! String)
        let validCiphertext = unhex(share["ciphertext_hex"] as! String)
        let alicePriv = unhex(alice["priv_hex"] as! String)
        let alicePub = unhex(alice["pub_hex"] as! String)
        let bobPub = unhex(bob["pub_hex"] as! String)
        let bobPriv = unhex(bob["priv_hex"] as! String)

        // The wrapped key itself was the one key-typed parameter in `share`
        // with no length check at all.
        XCTAssertThrowsError(try IdentityBox.share(
            key: [UInt8](repeating: 0, count: 16),
            nonce: validNonce, recipientPublicKey: bobPub, senderPrivateKey: alicePriv)) { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: 16))
        }

        XCTAssertThrowsError(try IdentityBox.share(
            key: plaintext, nonce: validNonce,
            recipientPublicKey: [UInt8](repeating: 0, count: 16), senderPrivateKey: alicePriv)) { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: 16))
        }

        XCTAssertThrowsError(try IdentityBox.share(
            key: plaintext, nonce: validNonce,
            recipientPublicKey: bobPub, senderPrivateKey: [UInt8](repeating: 0, count: 8))) { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: 8))
        }

        XCTAssertThrowsError(try IdentityBox.openShare(
            ciphertext: validCiphertext, nonce: validNonce,
            senderPublicKey: [UInt8](repeating: 0, count: 16), recipientPrivateKey: bobPriv)) { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: 16))
        }

        XCTAssertThrowsError(try IdentityBox.openShare(
            ciphertext: validCiphertext, nonce: validNonce,
            senderPublicKey: alicePub, recipientPrivateKey: [UInt8](repeating: 0, count: 8))) { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: 8))
        }
    }

    /// A bare 16-byte tag authenticates under swift-sodium's own length check
    /// (`>= MacBytes`) and would unwrap to [] - an EMPTY COLLECTION KEY
    /// returned as success. Same defect shape as KeyBox.open.
    ///
    /// The ciphertext here is a REAL crypto_box seal of an empty message
    /// between two real X25519 keypairs - not an arbitrary 16 zero bytes,
    /// which would not authenticate at all and would prove nothing about
    /// this guard.
    func testTagOnlyCiphertextIsRejected() throws {
        let id = try Vectors.section("identity")
        let alice = id["alice"] as! [String: Any]
        let bob = id["bob"] as! [String: Any]
        let alicePriv = unhex(alice["priv_hex"] as! String)
        let bobPub = unhex(bob["pub_hex"] as! String)
        let bobPriv = unhex(bob["priv_hex"] as! String)
        let alicePub = unhex(alice["pub_hex"] as! String)

        // This module exists to prevent exactly one (shared secret, nonce)
        // pair from encrypting two messages, so its own test suite must not
        // contain an example of that. Flip a byte off the fixture's
        // share_alice_to_bob nonce rather than reusing it verbatim - reusing
        // it as-is would put this tag-only seal and the fixture's real
        // 32-byte share ciphertext under the same Alice->Bob shared secret
        // AND the same nonce, i.e. two messages under one Poly1305 one-time
        // key.
        var nonce = unhex((id["share_alice_to_bob"] as! [String: Any])["nonce_hex"] as! String)
        nonce[0] ^= 0x01

        let tagOnlyCiphertext = Sodium().box.seal(
            message: [], recipientPublicKey: bobPub, senderSecretKey: alicePriv, nonce: nonce)!
        XCTAssertEqual(tagOnlyCiphertext.count, MantelCryptoConstants.tagBytes)

        XCTAssertThrowsError(try IdentityBox.openShare(
            ciphertext: tagOnlyCiphertext, nonce: nonce,
            senderPublicKey: alicePub, recipientPrivateKey: bobPriv)) { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidInput("ciphertext carries no plaintext: must be longer than the authentication tag"))
        }
    }
}
