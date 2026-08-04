import XCTest
import Sodium
@testable import MantelCrypto

final class KeyBoxTests: XCTestCase {

    /// The fixture pins every wrap site in the key hierarchy: master key under
    /// the KEK, master key under the recovery key (the second, independent
    /// unlock path), identity private key, collection key, file key, and the
    /// photo metadata blob.
    func testEveryWrapSiteMatchesFixture() throws {
        let keybox = try Vectors.section("keybox")
        var checked = 0
        for (site, raw) in keybox {
            guard let entry = raw as? [String: Any] else { continue }
            let plaintext: [UInt8]
            if let h = entry["plaintext_hex"] as? String {
                plaintext = unhex(h)
            } else if let s = entry["plaintext_utf8"] as? String {
                plaintext = Array(s.utf8)
            } else {
                XCTFail("wrap site '\(site)' has no plaintext"); continue
            }
            let ct = try KeyBox.seal(
                plaintext: plaintext,
                nonce: unhex(entry["nonce_hex"] as! String),
                wrappingKey: unhex(entry["wrapping_key_hex"] as! String))
            XCTAssertEqual(hex(ct), entry["ciphertext_hex"] as! String, "seal mismatch at '\(site)'")

            let back = try KeyBox.open(
                ciphertext: ct,
                nonce: unhex(entry["nonce_hex"] as! String),
                wrappingKey: unhex(entry["wrapping_key_hex"] as! String))
            XCTAssertEqual(hex(back), hex(plaintext), "open mismatch at '\(site)'")
            checked += 1
        }
        XCTAssertGreaterThanOrEqual(checked, 6, "expected at least 6 wrap sites in the fixture")
    }

    /// The fixture ships this negative case so both platforms agree on what
    /// "rejected" means.
    func testFixtureWrongWrappingKeyIsRejected() throws {
        let neg = try Vectors.section("negative")
        let c = neg["keybox_wrong_wrapping_key"] as! [String: Any]
        XCTAssertEqual(c["must_fail"] as? Bool, true)
        XCTAssertThrowsError(try KeyBox.open(
            ciphertext: unhex(c["ciphertext_hex"] as! String),
            nonce: unhex(c["nonce_hex"] as! String),
            wrappingKey: unhex(c["wrong_wrapping_key_hex"] as! String))) { error in
            XCTAssertEqual(error as? CryptoError, .authenticationFailed)
        }
    }

    func testTamperedCiphertextIsRejected() throws {
        let entry = try Vectors.section("keybox")["file_key_by_collection"] as! [String: Any]
        var ct = unhex(entry["ciphertext_hex"] as! String)
        ct[0] ^= 0x01
        XCTAssertThrowsError(try KeyBox.open(
            ciphertext: ct,
            nonce: unhex(entry["nonce_hex"] as! String),
            wrappingKey: unhex(entry["wrapping_key_hex"] as! String)))
    }

    func testTamperedNonceIsRejected() throws {
        let entry = try Vectors.section("keybox")["file_key_by_collection"] as! [String: Any]
        var nonce = unhex(entry["nonce_hex"] as! String)
        nonce[0] ^= 0x01
        XCTAssertThrowsError(try KeyBox.open(
            ciphertext: unhex(entry["ciphertext_hex"] as! String),
            nonce: nonce,
            wrappingKey: unhex(entry["wrapping_key_hex"] as! String)))
    }

    func testRejectsWrongNonceLength() {
        XCTAssertThrowsError(try KeyBox.seal(
            plaintext: [1, 2, 3],
            nonce: [UInt8](repeating: 0, count: 23),
            wrappingKey: [UInt8](repeating: 0, count: 32)))
    }

    /// A bare 16-byte tag authenticates and would unwrap to [] - an EMPTY
    /// MASTER KEY returned as success. This class wraps key material, but
    /// also (spec §7.4) the photo metadata blob, the album name, and the
    /// reaction emoji, so a zero-length "success" is never legitimate here.
    ///
    /// The ciphertext here is a REAL secretbox seal of an empty message -
    /// not an arbitrary 16 zero bytes, which would not authenticate at all
    /// and would prove nothing about this guard. Produced via the
    /// underlying Sodium primitive directly, since KeyBox.seal itself now
    /// refuses to produce one (that is the seal-side half of this fix).
    func testTagOnlyCiphertextIsRejected() {
        let key = [UInt8](repeating: 5, count: 32)
        let nonce = [UInt8](repeating: 6, count: 24)
        let tagOnlyCiphertext = Sodium().secretBox.seal(message: [], secretKey: key, nonce: nonce)!
        XCTAssertEqual(tagOnlyCiphertext.count, MantelCryptoConstants.tagBytes)

        XCTAssertThrowsError(try KeyBox.open(
            ciphertext: tagOnlyCiphertext, nonce: nonce, wrappingKey: key)) { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidInput("ciphertext carries no plaintext: must be longer than the authentication tag"))
        }
    }

    /// seal() must refuse to produce exactly the ciphertext open() just
    /// rejected above - otherwise a successful seal([]) would persist a
    /// tag-only ciphertext that can never be opened again.
    func testEmptyPlaintextIsRejected() {
        XCTAssertThrowsError(try KeyBox.seal(
            plaintext: [],
            nonce: [UInt8](repeating: 0, count: 24),
            wrappingKey: [UInt8](repeating: 0, count: 32))) { error in
            XCTAssertEqual(error as? CryptoError, .invalidInput("nothing to wrap: plaintext is empty"))
        }
    }
}
