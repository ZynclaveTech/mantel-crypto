import Foundation
import XCTest

/// Loads the shared test-vector fixture produced by the Node reference
/// implementation at `tools/vectors/`.
///
/// The fixture is the CONTRACT: this package must reproduce it byte for byte.
/// It is read-only here, and no test may ever write to it. The protocol this
/// replaces generated its vectors FROM the iOS test suite, which made iOS the
/// oracle - so an iOS bug became the specification, and Android faithfully
/// conformed to it.
enum Vectors {
    /// Absolute path to the fixture, derived from this file's own location at
    /// compile time. Walks up from
    ///   ios/MantelCrypto/Tests/MantelCryptoTests/Vectors.swift
    /// to the repository root, then down to the fixture. Using #filePath keeps
    /// the fixture out of the test bundle's resources, so the package needs no
    /// resource-copying build phase.
    static var path: String {
        // Five calls: the first strips the filename, the next four strip
        // MantelCryptoTests / Tests / MantelCrypto / ios, landing on the
        // repository root. Count them against the real depth if this ever
        // moves - an off-by-one here yields ios/tools/vectors/vectors.json,
        // which does not exist.
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // .../Tests/MantelCryptoTests
            .deletingLastPathComponent()   // .../Tests
            .deletingLastPathComponent()   // .../MantelCrypto
            .deletingLastPathComponent()   // .../ios
            .deletingLastPathComponent()   // repository root
            .appendingPathComponent("tools/vectors/vectors.json")
            .path
    }

    static func load() throws -> [String: Any] {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw CocoaError(.propertyListReadCorrupt)
        }
        return obj
    }

    /// Convenience accessor that fails the test with a useful message rather
    /// than crashing on a force-unwrap when the fixture shape changes.
    static func section(_ name: String, file: StaticString = #filePath, line: UInt = #line) throws -> [String: Any] {
        let v = try load()
        guard let s = v[name] as? [String: Any] else {
            XCTFail("fixture section '\(name)' missing or not an object", file: file, line: line)
            throw CocoaError(.propertyListReadCorrupt)
        }
        return s
    }

    static func array(_ name: String, file: StaticString = #filePath, line: UInt = #line) throws -> [[String: Any]] {
        let v = try load()
        guard let s = v[name] as? [[String: Any]] else {
            XCTFail("fixture section '\(name)' missing or not an array", file: file, line: line)
            throw CocoaError(.propertyListReadCorrupt)
        }
        return s
    }
}

func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func unhex(_ s: String) -> [UInt8] {
    var out = [UInt8]()
    out.reserveCapacity(s.count / 2)
    var i = s.startIndex
    while i < s.endIndex, let j = s.index(i, offsetBy: 2, limitedBy: s.endIndex) {
        out.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return out
}
