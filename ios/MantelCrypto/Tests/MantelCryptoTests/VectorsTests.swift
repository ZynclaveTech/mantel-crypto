import XCTest
@testable import MantelCrypto

final class VectorsTests: XCTestCase {
    func testFixtureLoadsWithEverySection() throws {
        let v = try Vectors.load()
        for section in ["kdf", "subkeys", "keybox", "identity", "stream", "negative", "safety_number"] {
            XCTAssertNotNil(v[section], "fixture is missing section '\(section)'")
        }
    }

    func testHexRoundTrips() {
        XCTAssertEqual(hex(unhex("00ff10")), "00ff10")
        XCTAssertEqual(unhex("00ff10"), [0, 255, 16])
    }

    func testWireConstantsMatchSpec() {
        XCTAssertEqual(MantelCryptoConstants.chunkSize, 8 * 1024 * 1024)
        XCTAssertEqual(MantelCryptoConstants.noncePrefixBytes, 19)
        XCTAssertEqual(MantelCryptoConstants.tagBytes, 16)
        XCTAssertEqual(MantelCryptoConstants.authContext, "mantelAu")
        XCTAssertEqual(MantelCryptoConstants.variantContext, "mantelFV")
        // crypto_kdf contexts are exactly 8 bytes. This is wire spec.
        XCTAssertEqual(MantelCryptoConstants.authContext.utf8.count, 8)
        XCTAssertEqual(MantelCryptoConstants.variantContext.utf8.count, 8)
    }
}
