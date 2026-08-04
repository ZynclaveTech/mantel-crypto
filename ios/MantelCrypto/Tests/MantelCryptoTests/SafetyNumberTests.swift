import XCTest
@testable import MantelCrypto

final class SafetyNumberTests: XCTestCase {

    func testAliceBobMatchesFixture() throws {
        let id = try Vectors.section("identity")
        let sn = try Vectors.section("safety_number")
        let alice = id["alice"] as! [String: Any]
        let bob = id["bob"] as! [String: Any]

        let computed = try SafetyNumber.compute(
            publicKeyA: unhex(alice["pub_hex"] as! String), subA: alice["sub"] as! String,
            publicKeyB: unhex(bob["pub_hex"] as! String), subB: bob["sub"] as! String)
        XCTAssertEqual(computed, sn["alice_bob"] as! String)
        XCTAssertEqual(computed.count, 60)
        XCTAssertTrue(computed.allSatisfy { $0.isASCII && $0.isNumber })
    }

    /// Both parties read the number off their own screens, so argument order
    /// cannot matter.
    func testIsSymmetric() throws {
        let id = try Vectors.section("identity")
        let sn = try Vectors.section("safety_number")
        let alice = id["alice"] as! [String: Any]
        let bob = id["bob"] as! [String: Any]

        let ab = try SafetyNumber.compute(
            publicKeyA: unhex(alice["pub_hex"] as! String), subA: alice["sub"] as! String,
            publicKeyB: unhex(bob["pub_hex"] as! String), subB: bob["sub"] as! String)
        let ba = try SafetyNumber.compute(
            publicKeyA: unhex(bob["pub_hex"] as! String), subA: bob["sub"] as! String,
            publicKeyB: unhex(alice["pub_hex"] as! String), subB: alice["sub"] as! String)
        XCTAssertEqual(ab, ba)
        XCTAssertEqual(ab, sn["bob_alice_must_match"] as! String)
    }

    /// The fixture pins each party's own 30-digit half. Reachable now that
    /// `digits(for:)` is `internal` instead of `private` - closes the
    /// coverage gap noted in issue #88 item 2, where iOS could previously
    /// only test the combined 60-digit number.
    func testPerPartyDigitsMatchFixture() throws {
        let id = try Vectors.section("identity")
        let sn = try Vectors.section("safety_number")
        for (party, key) in [("alice", "alice_digits"), ("bob", "bob_digits"), ("mallory", "mallory_digits")] {
            let p = id[party] as! [String: Any]
            let digits = try SafetyNumber.digits(for: unhex(p["pub_hex"] as! String), identifier: p["sub"] as! String)
            XCTAssertEqual(digits, sn[key] as! String, "\(party) digits")
            XCTAssertEqual(digits.count, 30)
        }

        // All 18 fixture groups happen to be >= 10000, so digits(for:)'s
        // String(format: "%05d") never actually has to pad for alice, bob or
        // mallory: iOS is structurally safer here than a trailing
        // `.padStart` would be - `%05d` cannot be "deleted" the same way a
        // suffix call can - but no iOS test exercises a sub-10000 group
        // either, which is the coverage gap issue #88 item 5 names. This
        // key/identifier pair is the same one Android's
        // `perPartyDigitsMatchFixture` uses to hit that branch (its fourth
        // group is 3252, which renders as "03252" only if padding applies);
        // since both platforms compute the same digits from the same input,
        // it hits the same branch here. Structural assertion on length by
        // design: a hardcoded expected string computed from this same
        // implementation would be circular.
        let paddingKey = [UInt8](repeating: 0x01, count: MantelCryptoConstants.keyBytes)
        let paddingId = "00000000-0000-4000-8000-000000000000"
        let padded = try SafetyNumber.digits(for: paddingKey, identifier: paddingId)
        XCTAssertEqual(padded.count, 30, "a group below 10000 must still render as 5 digits")
        XCTAssertTrue(padded.allSatisfy { $0.isASCII && $0.isNumber })
    }

    /// Byte-identical keys have no byte order, so the tie-break falls back to
    /// comparing rendered digit strings. That fallback must still be
    /// symmetric regardless of argument order - this is what issue #88 item 3
    /// calls out: the old `a.count <= b.count` tail always returned true for
    /// equal-length identical keys, so `compute(K, x, K, y)` and
    /// `compute(K, y, K, x)` produced different 60-digit numbers.
    func testIsSymmetricWhenKeysAreByteIdentical() throws {
        let key = [UInt8](repeating: 0x42, count: MantelCryptoConstants.keyBytes)
        let xy = try SafetyNumber.compute(publicKeyA: key, subA: "member-x", publicKeyB: key, subB: "member-y")
        let yx = try SafetyNumber.compute(publicKeyA: key, subA: "member-y", publicKeyB: key, subB: "member-x")
        XCTAssertEqual(xy, yx)
        XCTAssertEqual(xy.count, 60)
    }

    /// A substituted key must change the number - that is the whole point of
    /// showing it to a human.
    func testImpostorKeyChangesTheNumber() throws {
        let id = try Vectors.section("identity")
        let sn = try Vectors.section("safety_number")
        let alice = id["alice"] as! [String: Any]
        let mallory = id["mallory"] as! [String: Any]

        let computed = try SafetyNumber.compute(
            publicKeyA: unhex(alice["pub_hex"] as! String), subA: alice["sub"] as! String,
            publicKeyB: unhex(mallory["pub_hex"] as! String), subB: mallory["sub"] as! String)
        XCTAssertEqual(computed, sn["alice_mallory"] as! String)
        XCTAssertNotEqual(computed, sn["alice_bob"] as! String)
    }

    func testRejectsWrongKeyLength() {
        XCTAssertThrowsError(try SafetyNumber.compute(
            publicKeyA: [UInt8](repeating: 0, count: 31), subA: "a",
            publicKeyB: [UInt8](repeating: 1, count: 32), subB: "b"))
    }

    /// Issue #88 item 7: `digits(for:)` had no length guard of its own -
    /// unreachable from `compute` (which validates first), but a live
    /// divergence from Android's `digitsFor`, which calls `requireKey` and
    /// asserts this exact case (`digitsFor(ByteArray(31), "a")` throws).
    func testDigitsForRejectsWrongKeyLength() {
        XCTAssertThrowsError(try SafetyNumber.digits(for: [UInt8](repeating: 0, count: 31), identifier: "a")) {
            XCTAssertEqual(
                $0 as? CryptoError,
                CryptoError.invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: 31))
        }
    }
}
