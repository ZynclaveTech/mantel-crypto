import XCTest
@testable import MantelCrypto

final class PasswordKDFTests: XCTestCase {

    /// Every Argon2id tier in the fixture must reproduce. All three are part of
    /// the contract because the spec stores the parameters PER USER: a device
    /// enrolled at 64 MiB must still log in after the default is raised.
    func testAllArgon2idTiersMatchFixture() throws {
        let tiers = try Vectors.array("kdf")
        XCTAssertEqual(tiers.count, 3, "expected default/mid/low")
        for tier in tiers {
            let kek = try PasswordKDF.deriveKEK(
                password: tier["password"] as! String,
                salt: unhex(tier["salt_hex"] as! String),
                memlimit: tier["memlimit"] as! Int,
                opslimit: tier["opslimit"] as! Int
            )
            XCTAssertEqual(hex(kek), tier["kek_hex"] as! String,
                           "KEK mismatch at tier \(tier["tier"] as! String)")
        }
    }

    /// Split out from testAllArgon2idTiersMatchFixture so pinning
    /// `PasswordKDF.tiers` against the fixture ladder does not sit behind
    /// three real Argon2id derivations at 256/128/64 MiB. This is pure data
    /// comparison - no crypto - so it does not need to be there: a `try`
    /// failure in the derivation loop above would abort the function before
    /// these assertions ran, meaning a changed tier throws from `deriveKEK`
    /// before its own "the ladder has been widened" diagnostic ever fires,
    /// and an allocation failure at 256 MiB on a constrained CI container
    /// would skip the membership check entirely even though it needs no
    /// allocation of its own. Same masking shape that
    /// testUnapprovedKDFParametersAreRejected below was already extracted
    /// to avoid.
    func testTiersMatchTheFixtureLadder() throws {
        let tiers = try Vectors.array("kdf")
        XCTAssertEqual(tiers.count, 3, "expected default/mid/low")

        // PasswordKDF.tiers is the whitelist that #83 depends on, and it has
        // no other reference in this test target. Pinning it in BOTH
        // directions matters: fixture-subset-of-tiers alone would not catch
        // the ladder being WIDENED (e.g. a stray weak tier appended), and
        // tiers-subset-of-fixture alone would not catch a tier being
        // changed to the wrong params. Only asserting set equality catches
        // both.
        XCTAssertEqual(PasswordKDF.tiers.count, tiers.count,
                       "PasswordKDF.tiers must have exactly the tiers the fixture pins - not more, not fewer")
        for tier in tiers {
            let memlimit = tier["memlimit"] as! Int
            let opslimit = tier["opslimit"] as! Int
            XCTAssertTrue(
                PasswordKDF.tiers.contains { $0.memlimit == memlimit && $0.opslimit == opslimit },
                "fixture tier \(tier["tier"] as! String) (memlimit=\(memlimit), opslimit=\(opslimit)) has no exact match in PasswordKDF.tiers")
        }
        for t in PasswordKDF.tiers {
            XCTAssertTrue(
                tiers.contains { ($0["memlimit"] as! Int) == t.memlimit && ($0["opslimit"] as! Int) == t.opslimit },
                "PasswordKDF.tiers entry \(t.name) (memlimit=\(t.memlimit), opslimit=\(t.opslimit)) is not one of the fixture's pinned tiers - the ladder has been widened")
        }
    }

    /// Split out from testAllArgon2idTiersMatchFixture so an unrelated
    /// fixture regression in one of the three real Argon2id hashes there
    /// cannot abort the function before this - the actual security
    /// assertion for #83 - gets to run.
    func testUnapprovedKDFParametersAreRejected() throws {
        // The ladder is a whitelist, not documentation. Per spec 5.3 these
        // parameters arrive from an unauthenticated endpoint, so an operator
        // serving mem=8KiB/ops=1 would otherwise get the client to derive a
        // weak KEK and hand the resulting loginKey to Cognito - one cheap
        // Argon2id inversion away from the plaintext password.
        XCTAssertThrowsError(try PasswordKDF.deriveKEK(
            password: "correct horse battery staple",
            salt: [UInt8](repeating: 0, count: 16),
            memlimit: 8192, opslimit: 1)) { error in
            XCTAssertEqual(error as? CryptoError,
                           .unapprovedKDFParameters(memlimit: 8192, opslimit: 1))
        }

        // Do not delete this one - it looks redundant with the case above
        // but it is the one that actually distinguishes an exact-pair
        // whitelist from a floor check. 64 MiB is the ladder's memory floor
        // (the "low" tier) and 4 is its ops floor (the "default" tier), but
        // no tier pairs them together, so this combination is strictly
        // weaker than every real tier. A wrong implementation like
        // `memlimit >= 64 MiB && opslimit >= 4` would ACCEPT it; only the
        // correct exact-pair check rejects it.
        XCTAssertThrowsError(try PasswordKDF.deriveKEK(
            password: "correct horse battery staple",
            salt: [UInt8](repeating: 0, count: 16),
            memlimit: 64 * 1024 * 1024, opslimit: 4)) { error in
            XCTAssertEqual(error as? CryptoError,
                           .unapprovedKDFParameters(memlimit: 64 * 1024 * 1024, opslimit: 4))
        }
    }

    func testLoginKeyMatchesFixture() throws {
        for tier in try Vectors.array("kdf") {
            let kek = unhex(tier["kek_hex"] as! String)
            let login = try PasswordKDF.deriveLoginKey(kek: kek)
            XCTAssertEqual(hex(login), tier["login_key_hex"] as! String)
            XCTAssertEqual(Data(login).base64EncodedString(), tier["login_key_b64"] as! String)
            // If these matched, the server would effectively hold the KEK.
            XCTAssertNotEqual(hex(login), hex(kek))
        }
    }

    func testVariantSubkeysMatchFixture() throws {
        let sk = try Vectors.section("subkeys")
        let fileKey = unhex(sk["file_key_hex"] as! String)
        let context = sk["context"] as! String
        for variant in sk["variants"] as! [[String: Any]] {
            let derived = try PasswordKDF.deriveSubkey(
                key: fileKey, index: UInt64(variant["id"] as! Int), context: context)
            XCTAssertEqual(hex(derived), variant["subkey_hex"] as! String,
                           "subkey mismatch for variant \(variant["name"] as! String)")

            // The production helper must produce the same bytes as the raw
            // derivation with the fixture's context: without it,
            // variantContext has no caller in Sources/ and every variant
            // would be encrypted under the raw file key - a recoverable
            // two-time pad.
            let viaHelper = try PasswordKDF.deriveVariantKey(
                fileKey: fileKey, variantId: UInt8(variant["id"] as! Int))
            XCTAssertEqual(hex(viaHelper), variant["subkey_hex"] as! String,
                           "deriveVariantKey mismatch for variant \(variant["name"] as! String)")
        }

        XCTAssertThrowsError(try PasswordKDF.deriveVariantKey(fileKey: fileKey, variantId: 0)) { error in
            guard case .invalidInput = error as? CryptoError else {
                return XCTFail("variantId 0 must be rejected with .invalidInput, got \(error)")
            }
        }
        XCTAssertThrowsError(try PasswordKDF.deriveVariantKey(fileKey: fileKey, variantId: 4)) { error in
            guard case .invalidInput = error as? CryptoError else {
                return XCTFail("variantId 4 must be rejected with .invalidInput, got \(error)")
            }
        }
    }

    func testRejectsWrongSizedKey() {
        XCTAssertThrowsError(try PasswordKDF.deriveLoginKey(kek: [UInt8](repeating: 0, count: 31)))
    }
}
