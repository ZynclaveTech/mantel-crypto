import XCTest
@testable import MantelCrypto

final class ContentStreamTests: XCTestCase {

    func testNonceLayoutMatchesFixture() throws {
        let stream = try Vectors.section("stream")
        let examples = stream["nonce_examples"] as! [[String: Any]]
        XCTAssertFalse(examples.isEmpty)
        // NOTE: the fixture does not carry a per-example nonce_prefix_hex -
        // all nonce_examples share one prefix at the section level,
        // `nonce_examples_prefix_hex`. See report for details.
        let prefix = unhex(stream["nonce_examples_prefix_hex"] as! String)
        for ex in examples {
            let n = try ContentStream.buildNonce(
                prefix: prefix,
                counter: UInt32(ex["counter"] as! Int),
                isFinal: ex["is_final"] as! Bool)
            XCTAssertEqual(hex(n), ex["nonce_hex"] as! String,
                           "nonce mismatch at counter \(ex["counter"]!)")
        }
        // The fixture pins counters past 255 and 65535 specifically so a
        // single-byte or little-endian counter cannot pass.
        let counters = examples.map { $0["counter"] as! Int }
        XCTAssertTrue(counters.contains { $0 > 65535 }, "fixture must exercise a large counter")
    }

    /// Every case must reproduce, AND its key must be the variant subkey -
    /// never the raw file key. A whole-branch review of the reference
    /// implementation caught precisely that defect: sharing one key and one
    /// nonce prefix across variants produced a recoverable two-time pad.
    func testEveryStreamCaseMatchesFixture() throws {
        let stream = try Vectors.section("stream")
        let subkeys = try Vectors.section("subkeys")
        let variants = subkeys["variants"] as! [[String: Any]]
        let fileId = unhex(stream["file_id_hex"] as! String)
        let cases = stream["cases"] as! [[String: Any]]

        // Two-time-pad guard, nonce-prefix half: the subkey check in the loop
        // below only pins that each case uses its variant subkey. A shared
        // key AND a shared nonce prefix across variants is what actually
        // produces a recoverable two-time pad, so distinct variant_ids must
        // never share a prefix. Cases with the SAME variant_id legitimately
        // reuse a prefix.
        //
        // Both guards compare ACROSS variants, so both perform zero
        // comparisons - and pass - if the fixture ever regresses to a single
        // variant_id. Pin that the fixture actually exercises all three,
        // otherwise the guard for the exact defect this rewrite exists to
        // remove would go silently vacuous (or silently weaker) on the next
        // fixture regeneration. Floor is 3, not 2: the fixture now carries
        // all three protocol variants (thumb/preview/original), and pinning
        // at 2 would let a regression that drops variant 3 pass silently.
        let distinctVariantIds = Set(cases.map { $0["variant_id"] as! Int })
        XCTAssertGreaterThanOrEqual(
            distinctVariantIds.count, 3,
            "fixture must exercise all three distinct variant_ids, found \(distinctVariantIds) - " +
                "with fewer than three variants the cross-variant nonce-prefix and subkey guards below " +
                "compare less than the fixture is meant to cover (or nothing at all, and pass vacuously)")

        var prefixesByVariant: [Int: Set<String>] = [:]
        for c in cases {
            let vId = c["variant_id"] as! Int
            let prefixHex = c["nonce_prefix_hex"] as! String
            for (otherVariant, otherPrefixes) in prefixesByVariant {
                if otherVariant != vId && otherPrefixes.contains(prefixHex) {
                    XCTFail(
                        "nonce_prefix_hex \(prefixHex) is shared between variant \(vId) and " +
                            "variant \(otherVariant) - two-time pad")
                }
            }
            prefixesByVariant[vId, default: []].insert(prefixHex)
        }

        for c in cases {
            let variantId = UInt8(c["variant_id"] as! Int)
            let key = unhex(c["key_hex"] as! String)

            // Composition check: the content key IS the variant subkey.
            let expectedSubkey = variants.first { $0["id"] as! Int == Int(variantId) }!["subkey_hex"] as! String
            XCTAssertEqual(c["key_hex"] as! String, expectedSubkey,
                           "case \(c["name"]!) must use the variant subkey, not the raw file key")

            let chunks = try ContentStream.encrypt(
                plaintext: unhex(c["plaintext_hex"] as! String),
                key: key,
                noncePrefix: unhex(c["nonce_prefix_hex"] as! String),
                fileId: fileId,
                variantId: variantId,
                chunkSize: c["chunk_size"] as! Int)

            let expected = c["chunks_hex"] as! [String]
            XCTAssertEqual(chunks.count, expected.count, "chunk count for \(c["name"]!)")
            for (i, chunk) in chunks.enumerated() {
                XCTAssertEqual(hex(chunk), expected[i], "chunk \(i) of \(c["name"]!)")
            }

            let back = try ContentStream.decrypt(
                chunks: chunks, key: key,
                noncePrefix: unhex(c["nonce_prefix_hex"] as! String),
                fileId: fileId, variantId: variantId)
            XCTAssertEqual(hex(back), c["plaintext_hex"] as! String, "round trip for \(c["name"]!)")
        }
    }

    /// The reason STREAM was chosen over libsodium's secretstream: chunks
    /// decrypt independently, so video can seek without decrypting everything
    /// before the seek point.
    func testMiddleChunkDecryptsAlone() throws {
        let stream = try Vectors.section("stream")
        let c = (stream["cases"] as! [[String: Any]])
            .first { ($0["name"] as! String) == "multi_chunk_short_final" }!
        let chunks = (c["chunks_hex"] as! [String]).map(unhex)
        XCTAssertGreaterThan(chunks.count, 2)

        let plaintext = unhex(c["plaintext_hex"] as! String)
        let chunkSize = c["chunk_size"] as! Int
        let middle = try ContentStream.decryptChunk(
            chunks[1], index: 1, isFinal: false,
            key: unhex(c["key_hex"] as! String),
            noncePrefix: unhex(c["nonce_prefix_hex"] as! String),
            fileId: unhex(stream["file_id_hex"] as! String),
            variantId: UInt8(c["variant_id"] as! Int))
        XCTAssertEqual(hex(middle), hex(Array(plaintext[chunkSize..<(chunkSize * 2)])))
    }

    /// All the fixture's stream negatives, so iOS and Android reject the same
    /// inputs for the same reasons.
    func testFixtureNegativesAreAllRejected() throws {
        let neg = try Vectors.section("negative")

        let expectedNegatives = ["stream_truncated", "stream_reordered",
                                  "stream_spliced_from_other_file", "stream_relabelled_as_other_variant",
                                  "stream_empty_chunk_list", "stream_tampered_byte"]
        // Both lists here are hardcoded on purpose (they document intent and
        // keep the loop readable), but nothing previously forced either
        // client to notice a NEWLY ADDED fixture negative - it would simply
        // never be tested, on both platforms at once. Assert the hardcoded
        // list equals the fixture's actual stream_* negatives so a new one
        // fails the build until a client opts in.
        let fixtureStreamNegatives = Set(neg.keys.filter { $0.hasPrefix("stream_") })
        let missingFromThisTest = fixtureStreamNegatives.subtracting(expectedNegatives)
        XCTAssertTrue(
            missingFromThisTest.isEmpty,
            "fixture has stream negative(s) this test does not cover: \(missingFromThisTest) - " +
                "add them to the list in testFixtureNegativesAreAllRejected()")

        for name in expectedNegatives {
            let c = neg[name] as! [String: Any]
            XCTAssertEqual(c["must_fail"] as? Bool, true, "\(name) should be marked must_fail")
            let chunks = (c["chunks_hex"] as! [String]).map(unhex)
            let key = unhex(c["key_hex"] as! String)
            let noncePrefix = unhex(c["nonce_prefix_hex"] as! String)
            let fileId = unhex(c["file_id_hex"] as! String)
            // Each negative entry carries its OWN file_id_hex - use it, not the
            // top-level one. stream_spliced_from_other_file in particular must
            // be decrypted against the CLAIMED file's id so it fails on the
            // spliced chunk's AAD, rather than passing for the wrong reason.
            XCTAssertThrowsError(try ContentStream.decrypt(
                chunks: chunks, key: key, noncePrefix: noncePrefix, fileId: fileId,
                variantId: UInt8(c["variant_id"] as! Int)),
                "\(name) must be rejected")

            // Positive control: when the fixture also names the variant that
            // TRUTHFULLY encrypted this stream (other_variant_id), decrypting
            // the SAME chunks/key/prefix/fileId under that true variant MUST
            // SUCCEED. That proves the stream is well-formed and the failure
            // above is caused specifically by the claimed (wrong) variant_id
            // in the AAD - not by some unrelated defect that the negative's
            // `reason` string doesn't describe. Without this, a rejection for
            // the wrong reason is indistinguishable from a rejection for the
            // right one: exactly the bug this fixture's own variant-3 vector
            // first shipped with (wrong isFinal, misattributed to the AAD
            // variant byte), which both client suites reported green on.
            if let otherVariantId = c["other_variant_id"] as? Int {
                XCTAssertNoThrow(try ContentStream.decrypt(
                    chunks: chunks, key: key, noncePrefix: noncePrefix, fileId: fileId,
                    variantId: UInt8(otherVariantId)),
                    "\(name) must decrypt successfully under its true variant \(otherVariantId)")
            }
        }
    }

    func testEmptyChunkListIsRejected() {
        XCTAssertThrowsError(try ContentStream.decrypt(
            chunks: [], key: [UInt8](repeating: 1, count: 32),
            noncePrefix: [UInt8](repeating: 2, count: 19),
            fileId: [UInt8](repeating: 3, count: 16), variantId: 1)) { error in
            XCTAssertEqual(error as? CryptoError, .emptyStream)
        }
    }

    /// deriveVariantKey (PasswordKDF.swift) restricts variantId to 1...3.
    /// buildAAD must enforce the same range, or a Phase 2 caller could
    /// encrypt+upload with variantId 0 or 4 without complaint while every
    /// Android family member throws on decrypt - undecryptable data at
    /// rest, silent on the writing platform. All fixture stream cases use
    /// variantId 1, 2, or 3 (0, 4, and 255 below are all out of range), so
    /// this does not touch the fixture-matching suite above.
    func testBuildAADRejectsOutOfRangeVariantId() throws {
        let fileId = [UInt8](repeating: 7, count: 16)
        for variantId: UInt8 in [0, 4, 255] {
            XCTAssertThrowsError(try ContentStream.buildAAD(fileId: fileId, variantId: variantId)) { error in
                guard case .invalidInput = error as? CryptoError else {
                    return XCTFail("variantId \(variantId) must be rejected with .invalidInput, got \(error)")
                }
            }
        }
    }

    func testProductionChunkSizeIsEightMiB() throws {
        let stream = try Vectors.section("stream")
        XCTAssertEqual(stream["production_chunk_size"] as! Int, MantelCryptoConstants.chunkSize)
    }

    /// decrypt/decryptChunk reach a raw Clibsodium call that reads 32 bytes
    /// from `key` unconditionally - a short key is a read past the end of
    /// Swift-owned storage, not a graceful failure, unless this guard runs
    /// before that call. encrypt already had this guard; decrypt and
    /// decryptChunk did not.
    func testDecryptRejectsWrongSizedKey() throws {
        let stream = try Vectors.section("stream")
        let c = (stream["cases"] as! [[String: Any]]).first!
        let chunks = (c["chunks_hex"] as! [String]).map(unhex)
        let shortKey = [UInt8](repeating: 1, count: 31)

        XCTAssertThrowsError(try ContentStream.decrypt(
            chunks: chunks, key: shortKey,
            noncePrefix: unhex(c["nonce_prefix_hex"] as! String),
            fileId: unhex(stream["file_id_hex"] as! String),
            variantId: UInt8(c["variant_id"] as! Int))) { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: 31))
        }

        XCTAssertThrowsError(try ContentStream.decryptChunk(
            chunks[0], index: 0, isFinal: chunks.count == 1,
            key: shortKey,
            noncePrefix: unhex(c["nonce_prefix_hex"] as! String),
            fileId: unhex(stream["file_id_hex"] as! String),
            variantId: UInt8(c["variant_id"] as! Int))) { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: 31))
        }
    }

    /// The streaming write path: reproduce EVERY fixture stream case
    /// chunk-by-chunk through `ContentStream.encryptChunk` alone (never
    /// calling `ContentStream.encrypt`) and assert every chunk matches the
    /// fixture's `chunks_hex` exactly. Proves the streaming path a Phase 2
    /// uploader will actually use produces byte-identical output to the
    /// batch path the fixture already pins - across all five stream cases,
    /// including the empty-plaintext and exact-chunk-boundary edges, not
    /// just one hand-picked multi-chunk case.
    func testEncryptChunkReproducesFixtureChunkByChunk() throws {
        let stream = try Vectors.section("stream")
        let fileId = unhex(stream["file_id_hex"] as! String)

        for c in stream["cases"] as! [[String: Any]] {
            let key = unhex(c["key_hex"] as! String)
            let prefix = unhex(c["nonce_prefix_hex"] as! String)
            let variantId = UInt8(c["variant_id"] as! Int)
            let chunkSize = c["chunk_size"] as! Int
            let plaintext = unhex(c["plaintext_hex"] as! String)
            let expected = c["chunks_hex"] as! [String]

            for i in 0..<expected.count {
                let lo = i * chunkSize
                let hi = min(lo + chunkSize, plaintext.count)
                let slice = lo < hi ? Array(plaintext[lo..<hi]) : []
                let chunk = try ContentStream.encryptChunk(
                    slice, index: i, isFinal: i == expected.count - 1,
                    key: key, noncePrefix: prefix, fileId: fileId, variantId: variantId)
                XCTAssertEqual(hex(chunk), expected[i], "chunk \(i) of \(c["name"]!)")
            }
        }
    }

    /// The doc comment on `ContentStream.encryptChunk` claims that
    /// mis-placing `isFinal` produces a stream `decrypt` rejects outright.
    /// Exercise that through the public entry point: encrypt a multi-chunk
    /// fixture case but ALSO mark chunk 0 - never the final chunk in a
    /// multi-chunk stream - as `isFinal = true`, and confirm `decrypt`
    /// rejects the resulting stream. Flipping the final flag changes byte 23
    /// of the AEAD nonce for that chunk, so it fails authentication the same
    /// way a tampered nonce would.
    func testEncryptChunkWithMisplacedIsFinalIsRejectedByDecrypt() throws {
        let stream = try Vectors.section("stream")
        let c = (stream["cases"] as! [[String: Any]])
            .first { ($0["name"] as! String) == "multi_chunk_short_final" }!
        let fileId = unhex(stream["file_id_hex"] as! String)
        let key = unhex(c["key_hex"] as! String)
        let prefix = unhex(c["nonce_prefix_hex"] as! String)
        let variantId = UInt8(c["variant_id"] as! Int)
        let chunkSize = c["chunk_size"] as! Int
        let plaintext = unhex(c["plaintext_hex"] as! String)
        let total = (c["chunks_hex"] as! [String]).count
        XCTAssertGreaterThan(total, 2)

        var chunks = [[UInt8]]()
        for i in 0..<total {
            let lo = i * chunkSize
            let hi = min(lo + chunkSize, plaintext.count)
            let slice = lo < hi ? Array(plaintext[lo..<hi]) : []
            let correctIsFinal = i == total - 1
            // Deliberately mis-place isFinal: chunk 0 is never final in a
            // multi-chunk stream, but mark it isFinal = true anyway.
            let isFinal = i == 0 ? true : correctIsFinal
            chunks.append(try ContentStream.encryptChunk(
                slice, index: i, isFinal: isFinal,
                key: key, noncePrefix: prefix, fileId: fileId, variantId: variantId))
        }

        XCTAssertThrowsError(try ContentStream.decrypt(
            chunks: chunks, key: key, noncePrefix: prefix,
            fileId: fileId, variantId: variantId),
            "stream with isFinal misplaced on a non-final chunk must be rejected") { error in
            XCTAssertEqual(error as? CryptoError, .authenticationFailed)
        }
    }

    func testEncryptChunkRejectsWrongSizedKey() throws {
        let stream = try Vectors.section("stream")
        let c = (stream["cases"] as! [[String: Any]]).first!
        let fileId = unhex(stream["file_id_hex"] as! String)
        let shortKey = [UInt8](repeating: 1, count: 31)

        XCTAssertThrowsError(try ContentStream.encryptChunk(
            [UInt8](repeating: 0, count: 4), index: 0, isFinal: true,
            key: shortKey,
            noncePrefix: unhex(c["nonce_prefix_hex"] as! String),
            fileId: fileId, variantId: UInt8(c["variant_id"] as! Int))) { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: 31))
        }
    }

    /// Mirrors testBuildAADRejectsOutOfRangeVariantId but through the public
    /// entry point itself, since encryptChunk becoming public means it must
    /// carry the same variantId range check `encrypt` always has - routed
    /// through buildAAD, not duplicated.
    func testEncryptChunkRejectsOutOfRangeVariantId() throws {
        let stream = try Vectors.section("stream")
        let c = (stream["cases"] as! [[String: Any]]).first!
        let fileId = unhex(stream["file_id_hex"] as! String)
        let key = unhex(c["key_hex"] as! String)

        for variantId: UInt8 in [0, 4, 255] {
            XCTAssertThrowsError(try ContentStream.encryptChunk(
                [UInt8](repeating: 0, count: 4), index: 0, isFinal: true,
                key: key,
                noncePrefix: unhex(c["nonce_prefix_hex"] as! String),
                fileId: fileId, variantId: variantId)) { error in
                guard case .invalidInput = error as? CryptoError else {
                    return XCTFail("variantId \(variantId) must be rejected with .invalidInput, got \(error)")
                }
            }
        }
    }

    /// `index` is caller-supplied on both public streaming entry points - a
    /// Phase 2 uploader or player drives it directly - and `buildNonce` takes
    /// `counter: UInt32`. A bare `UInt32(index)` conversion at the call site
    /// traps on an out-of-range `index` (SIGTRAP, uncatchable) instead of
    /// throwing, so the private `nonce(forIndex:isFinal:noncePrefix:)` helper
    /// range-checks BEFORE converting. Pin that a negative index and one past
    /// the 32-bit counter range are both rejected with `.invalidInput`,
    /// matching Android's `Long`-typed `counter` and its guard in
    /// `buildNonce`.
    func testEncryptChunkRejectsOutOfRangeIndex() throws {
        let stream = try Vectors.section("stream")
        let c = (stream["cases"] as! [[String: Any]]).first!
        let fileId = unhex(stream["file_id_hex"] as! String)
        let key = unhex(c["key_hex"] as! String)
        let prefix = unhex(c["nonce_prefix_hex"] as! String)
        let variantId = UInt8(c["variant_id"] as! Int)

        for badIndex in [-1, Int(UInt32.max) + 1] {
            XCTAssertThrowsError(try ContentStream.encryptChunk(
                [UInt8](repeating: 0, count: 4), index: badIndex, isFinal: true,
                key: key, noncePrefix: prefix, fileId: fileId, variantId: variantId),
                "index \(badIndex) must be rejected") { error in
                guard case .invalidInput = error as? CryptoError else {
                    return XCTFail("index \(badIndex) must be rejected with .invalidInput, got \(error)")
                }
            }
        }

        // The top of the range is INCLUSIVE and must stay that way. Android
        // accepts counter == 0xFFFFFFFF, pinned by its nonceLayoutMatchesFixture
        // against the fixture's nonce_examples. iOS's guard lives in a private
        // helper that testNonceLayoutMatchesFixture bypasses (it calls
        // buildNonce directly), so without this assertion an off-by-one to
        // `index < Int(UInt32.max)` would compile, pass every other test, and
        // leave the two platforms disagreeing on the largest legal counter.
        XCTAssertNoThrow(try ContentStream.encryptChunk(
            [UInt8](repeating: 0, count: 4), index: Int(UInt32.max), isFinal: true,
            key: key, noncePrefix: prefix, fileId: fileId, variantId: variantId),
            "counter 0xFFFFFFFF is the largest legal index and must be accepted")
    }

    /// `seal`/`open` reach the raw Clibsodium AEAD calls with whatever nonce
    /// `buildNonce` built for them. That is sound today - `buildNonce`
    /// always emits exactly `MantelCryptoConstants.nonceBytes` bytes - but
    /// every public entry point routes through `buildNonce` before calling
    /// these, so there is no way to reach the guard through
    /// `encryptChunk`/`decryptChunk` with a malformed nonce; `buildNonce`
    /// itself would reject a wrong-sized prefix first. `seal`/`open` are
    /// package-internal, not `private`, specifically so `@testable import`
    /// lets this test call them directly and pin that they no longer take
    /// the nonce length on trust, matching the existing `keyBytes` guard for
    /// key arguments. This matters more here than on Android: these calls
    /// go straight to raw Clibsodium, which reads `nonceBytes` from the
    /// pointer unconditionally.
    func testSealAndOpenRejectWrongSizedNonce() throws {
        let stream = try Vectors.section("stream")
        let c = (stream["cases"] as! [[String: Any]]).first!
        let fileId = unhex(stream["file_id_hex"] as! String)
        let key = unhex(c["key_hex"] as! String)
        let variantId = UInt8(c["variant_id"] as! Int)
        let aad = try ContentStream.buildAAD(fileId: fileId, variantId: variantId)
        let wrongNonce = [UInt8](repeating: 0, count: MantelCryptoConstants.nonceBytes - 1)

        XCTAssertThrowsError(try ContentStream.seal([0, 1, 2, 3], aad: aad, nonce: wrongNonce, key: key),
                             "seal must reject a wrong-sized nonce") { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidNonceLength(expected: MantelCryptoConstants.nonceBytes,
                                                got: wrongNonce.count))
        }

        let chunk = unhex((c["chunks_hex"] as! [String])[0])
        XCTAssertThrowsError(try ContentStream.open(chunk, aad: aad, nonce: wrongNonce, key: key),
                             "open must reject a wrong-sized nonce") { error in
            XCTAssertEqual(error as? CryptoError,
                           .invalidNonceLength(expected: MantelCryptoConstants.nonceBytes,
                                                got: wrongNonce.count))
        }
    }

    func testDecryptChunkRejectsOutOfRangeIndex() throws {
        let stream = try Vectors.section("stream")
        let c = (stream["cases"] as! [[String: Any]]).first!
        let fileId = unhex(stream["file_id_hex"] as! String)
        let key = unhex(c["key_hex"] as! String)
        let prefix = unhex(c["nonce_prefix_hex"] as! String)
        let variantId = UInt8(c["variant_id"] as! Int)
        let chunk = unhex((c["chunks_hex"] as! [String])[0])

        for badIndex in [-1, Int(UInt32.max) + 1] {
            XCTAssertThrowsError(try ContentStream.decryptChunk(
                chunk, index: badIndex, isFinal: true,
                key: key, noncePrefix: prefix, fileId: fileId, variantId: variantId),
                "index \(badIndex) must be rejected") { error in
                guard case .invalidInput = error as? CryptoError else {
                    return XCTFail("index \(badIndex) must be rejected with .invalidInput, got \(error)")
                }
            }
        }
    }
}
