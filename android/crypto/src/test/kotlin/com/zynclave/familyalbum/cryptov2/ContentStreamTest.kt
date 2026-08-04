package com.zynclave.familyalbum.cryptov2

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ContentStreamTest {

    private val cs = ContentStream(testSodium)

    @Test
    fun nonceLayoutMatchesFixture() {
        val stream = Vectors.section("stream")
        // The prefix lives at section level, NOT on each example.
        val prefix = unhex(stream.getString("nonce_examples_prefix_hex"))
        val examples = Vectors.objects(stream.getJSONArray("nonce_examples"))
        assertTrue(examples.isNotEmpty())
        for (ex in examples) {
            val n = cs.buildNonce(prefix, ex.getLong("counter"), ex.getBoolean("is_final"))
            assertEquals(ex.getString("nonce_hex"), hex(n), "nonce mismatch at counter ${ex.getLong("counter")}")
        }
        // Counters past 65535 are pinned so a single-byte or little-endian
        // counter cannot pass.
        assertTrue(examples.any { it.getLong("counter") > 65535 }, "fixture must exercise a large counter")
    }

    /**
     * Every case must reproduce AND its key must be the variant subkey, never
     * the raw file key. A whole-branch review of the reference implementation
     * caught exactly that defect: sharing one key and one nonce prefix across
     * variants produced a recoverable two-time pad.
     */
    @Test
    fun everyStreamCaseMatchesFixture() {
        val stream = Vectors.section("stream")
        val variants = Vectors.objects(Vectors.section("subkeys").getJSONArray("variants"))
        val fileId = unhex(stream.getString("file_id_hex"))

        // Two-time-pad guard, nonce-prefix half: the key check below only pins
        // that each case uses its variant subkey. A shared key AND a shared
        // nonce prefix across variants is what actually produces a recoverable
        // two-time pad, so distinct variant_ids must never share a prefix.
        // Cases with the SAME variant_id legitimately reuse a prefix.
        //
        // Both guards compare ACROSS variants, so both perform zero comparisons
        // - and pass - if the fixture ever regresses to a single variant_id.
        // Pin that the fixture actually exercises more than one, otherwise the
        // guard for the exact defect this rewrite exists to remove would go
        // silently vacuous on the next fixture regeneration.
        val distinctVariantIds = Vectors.objects(stream.getJSONArray("cases"))
            .map { it.getInt("variant_id") }
            .toSet()
        assertTrue(
            // Floor is 3, not 2: the fixture now carries all three protocol
            // variants (thumb/preview/original). Pinning at 2 would let a
            // future regression that drops the variant-3 case pass silently,
            // quietly narrowing the two-time-pad guard below back to a
            // single cross-variant pair instead of failing the build.
            distinctVariantIds.size >= 3,
            "fixture must exercise all three distinct variant_ids, found $distinctVariantIds - " +
                "with fewer than three variants the cross-variant nonce-prefix and subkey guards below " +
                "compare less than the fixture is meant to cover (or nothing at all, and pass vacuously)",
        )

        val prefixesByVariant = mutableMapOf<Int, MutableSet<String>>()
        for (c in Vectors.objects(stream.getJSONArray("cases"))) {
            val vId = c.getInt("variant_id")
            val prefixHex = c.getString("nonce_prefix_hex")
            for ((otherVariant, otherPrefixes) in prefixesByVariant) {
                if (otherVariant != vId && prefixHex in otherPrefixes) {
                    throw AssertionError(
                        "nonce_prefix_hex $prefixHex is shared between variant $vId and " +
                            "variant $otherVariant - two-time pad",
                    )
                }
            }
            prefixesByVariant.getOrPut(vId) { mutableSetOf() }.add(prefixHex)
        }

        for (c in Vectors.objects(stream.getJSONArray("cases"))) {
            val variantId = c.getInt("variant_id")
            val key = unhex(c.getString("key_hex"))

            val expectedSubkey = variants.first { it.getInt("id") == variantId }.getString("subkey_hex")
            assertEquals(
                expectedSubkey, c.getString("key_hex"),
                "case ${c.getString("name")} must use the variant subkey, not the raw file key",
            )

            val prefix = unhex(c.getString("nonce_prefix_hex"))
            val chunks = cs.encrypt(
                plaintext = unhex(c.getString("plaintext_hex")),
                key = key, noncePrefix = prefix, fileId = fileId,
                variantId = variantId, chunkSize = c.getInt("chunk_size"),
            )
            val expected = c.getJSONArray("chunks_hex")
            assertEquals(expected.length(), chunks.size, "chunk count for ${c.getString("name")}")
            chunks.forEachIndexed { i, chunk ->
                assertEquals(expected.getString(i), hex(chunk), "chunk $i of ${c.getString("name")}")
            }
            assertEquals(
                c.getString("plaintext_hex"),
                hex(cs.decrypt(chunks, key, prefix, fileId, variantId)),
                "round trip for ${c.getString("name")}",
            )
        }
    }

    /** Why STREAM was chosen over secretstream: chunks decrypt independently. */
    @Test
    fun middleChunkDecryptsAlone() {
        val stream = Vectors.section("stream")
        val c = Vectors.objects(stream.getJSONArray("cases"))
            .first { it.getString("name") == "multi_chunk_short_final" }
        val chunks = (0 until c.getJSONArray("chunks_hex").length())
            .map { unhex(c.getJSONArray("chunks_hex").getString(it)) }
        assertTrue(chunks.size > 2)

        val plaintext = unhex(c.getString("plaintext_hex"))
        val chunkSize = c.getInt("chunk_size")
        val middle = cs.decryptChunk(
            chunk = chunks[1], index = 1, isFinal = false,
            key = unhex(c.getString("key_hex")),
            noncePrefix = unhex(c.getString("nonce_prefix_hex")),
            fileId = unhex(stream.getString("file_id_hex")),
            variantId = c.getInt("variant_id"),
        )
        assertEquals(hex(plaintext.copyOfRange(chunkSize, chunkSize * 2)), hex(middle))
    }

    /** All the fixture's stream negatives, so both platforms reject the same inputs. */
    @Test
    fun fixtureNegativesAreAllRejected() {
        val neg = Vectors.section("negative")

        val expectedNegatives = listOf(
            "stream_truncated", "stream_reordered", "stream_spliced_from_other_file",
            "stream_relabelled_as_other_variant", "stream_empty_chunk_list", "stream_tampered_byte",
        )
        // Both lists here are hardcoded on purpose (they document intent and
        // keep the loop readable), but nothing previously forced either
        // client to notice a NEWLY ADDED fixture negative - it would simply
        // never be tested, on both platforms at once. Assert the hardcoded
        // list equals the fixture's actual stream_* negatives so a new one
        // fails the build until a client opts in.
        val fixtureStreamNegatives = neg.keys().asSequence().filter { it.startsWith("stream_") }.toSet()
        val missingFromThisTest = fixtureStreamNegatives - expectedNegatives.toSet()
        assertTrue(
            missingFromThisTest.isEmpty(),
            "fixture has stream negative(s) this test does not cover: $missingFromThisTest - " +
                "add them to the list in fixtureNegativesAreAllRejected()",
        )

        for (name in expectedNegatives) {
            val c = neg.getJSONObject(name)
            assertTrue(c.getBoolean("must_fail"), "$name should be marked must_fail")
            val chunks = (0 until c.getJSONArray("chunks_hex").length())
                .map { unhex(c.getJSONArray("chunks_hex").getString(it)) }
            assertFailsWith<CryptoError>("$name must be rejected") {
                cs.decrypt(
                    chunks = chunks,
                    key = unhex(c.getString("key_hex")),
                    noncePrefix = unhex(c.getString("nonce_prefix_hex")),
                    // Each negative carries its OWN file_id_hex. Using it is what
                    // makes the splice case fail on the spliced chunk's AAD rather
                    // than passing for the wrong reason.
                    fileId = unhex(c.getString("file_id_hex")),
                    variantId = c.getInt("variant_id"),
                )
            }

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
            if (c.has("other_variant_id")) {
                cs.decrypt(
                    chunks = chunks,
                    key = unhex(c.getString("key_hex")),
                    noncePrefix = unhex(c.getString("nonce_prefix_hex")),
                    fileId = unhex(c.getString("file_id_hex")),
                    variantId = c.getInt("other_variant_id"),
                )
            }
        }
    }

    @Test
    fun emptyChunkListIsRejected() {
        assertFailsWith<CryptoError> {
            cs.decrypt(emptyList(), ByteArray(32) { 1 }, ByteArray(19) { 2 }, ByteArray(16) { 3 }, 1)
        }
    }

    @Test
    fun productionChunkSizeIsEightMiB() {
        assertEquals(WireConstants.CHUNK_SIZE, Vectors.section("stream").getInt("production_chunk_size"))
    }

    /**
     * The streaming write path: reproduce EVERY fixture stream case
     * chunk-by-chunk through [ContentStream.encryptChunk] alone (never calling
     * [ContentStream.encrypt]) and assert every chunk matches the fixture's
     * `chunks_hex` exactly. Proves the streaming path a Phase 2 uploader will
     * actually use produces byte-identical output to the batch path the
     * fixture already pins - across all five stream cases, including the
     * empty-plaintext and exact-chunk-boundary edges, not just one hand-picked
     * multi-chunk case.
     *
     * Chunking here is done in Long arithmetic deliberately, mirroring
     * [ContentStream.encrypt]'s own widening (see the comment there): at
     * fixture sizes Int would not overflow either way, but a test that
     * duplicates production's slicing math should not duplicate the
     * un-widened, overflow-prone form of it.
     */
    @Test
    fun encryptChunkReproducesFixtureChunkByChunk() {
        val stream = Vectors.section("stream")
        val fileId = unhex(stream.getString("file_id_hex"))
        for (c in Vectors.objects(stream.getJSONArray("cases"))) {
            val key = unhex(c.getString("key_hex"))
            val prefix = unhex(c.getString("nonce_prefix_hex"))
            val variantId = c.getInt("variant_id")
            val chunkSize = c.getInt("chunk_size")
            val plaintext = unhex(c.getString("plaintext_hex"))
            val expected = c.getJSONArray("chunks_hex")

            for (i in 0 until expected.length()) {
                val lo = i.toLong() * chunkSize
                val hi = minOf(lo + chunkSize, plaintext.size.toLong())
                val slice = if (lo < hi) plaintext.copyOfRange(lo.toInt(), hi.toInt()) else ByteArray(0)
                val chunk = cs.encryptChunk(
                    plaintext = slice,
                    index = i.toLong(),
                    isFinal = i == expected.length() - 1,
                    key = key, noncePrefix = prefix, fileId = fileId, variantId = variantId,
                )
                assertEquals(expected.getString(i), hex(chunk), "chunk $i of ${c.getString("name")}")
            }
        }
    }

    /**
     * The doc comment on [ContentStream.encryptChunk] claims that mis-placing
     * `isFinal` produces a stream [ContentStream.decrypt] rejects outright.
     * Exercise that through the public entry point: encrypt a multi-chunk
     * fixture case but ALSO mark chunk 0 - never the final chunk in a
     * multi-chunk stream - as `isFinal = true`, and confirm [ContentStream.decrypt]
     * rejects the resulting stream. Flipping the final flag changes byte 23 of
     * the AEAD nonce for that chunk, so it fails authentication the same way a
     * tampered nonce would.
     */
    @Test
    fun encryptChunkWithMisplacedIsFinalIsRejectedByDecrypt() {
        val stream = Vectors.section("stream")
        val c = Vectors.objects(stream.getJSONArray("cases"))
            .first { it.getString("name") == "multi_chunk_short_final" }
        val fileId = unhex(stream.getString("file_id_hex"))
        val key = unhex(c.getString("key_hex"))
        val prefix = unhex(c.getString("nonce_prefix_hex"))
        val variantId = c.getInt("variant_id")
        val chunkSize = c.getInt("chunk_size")
        val plaintext = unhex(c.getString("plaintext_hex"))
        val total = c.getJSONArray("chunks_hex").length()
        assertTrue(total > 2)

        val chunks = (0 until total).map { i ->
            val lo = i * chunkSize
            val hi = minOf(lo + chunkSize, plaintext.size)
            val slice = if (lo < hi) plaintext.copyOfRange(lo, hi) else ByteArray(0)
            val correctIsFinal = i == total - 1
            // Deliberately mis-place isFinal: chunk 0 is never final in a
            // multi-chunk stream, but mark it isFinal = true anyway.
            val isFinal = if (i == 0) true else correctIsFinal
            cs.encryptChunk(slice, i.toLong(), isFinal, key, prefix, fileId, variantId)
        }

        assertFailsWith<CryptoError.AuthenticationFailed>(
            "stream with isFinal misplaced on a non-final chunk must be rejected",
        ) {
            cs.decrypt(chunks, key, prefix, fileId, variantId)
        }
    }

    @Test
    fun encryptChunkRejectsWrongSizedKey() {
        val stream = Vectors.section("stream")
        val c = Vectors.objects(stream.getJSONArray("cases")).first()
        val fileId = unhex(stream.getString("file_id_hex"))
        val shortKey = ByteArray(31) { 1 }
        assertFailsWith<CryptoError.InvalidKeyLength> {
            cs.encryptChunk(
                plaintext = ByteArray(4),
                index = 0, isFinal = true,
                key = shortKey,
                noncePrefix = unhex(c.getString("nonce_prefix_hex")),
                fileId = fileId, variantId = c.getInt("variant_id"),
            )
        }
    }

    @Test
    fun encryptChunkRejectsOutOfRangeVariantId() {
        val stream = Vectors.section("stream")
        val c = Vectors.objects(stream.getJSONArray("cases")).first()
        val fileId = unhex(stream.getString("file_id_hex"))
        val key = unhex(c.getString("key_hex"))
        for (badVariantId in listOf(0, 4, 255)) {
            assertFailsWith<CryptoError.InvalidInput>("variantId $badVariantId must be rejected") {
                cs.encryptChunk(
                    plaintext = ByteArray(4),
                    index = 0, isFinal = true,
                    key = key,
                    noncePrefix = unhex(c.getString("nonce_prefix_hex")),
                    fileId = fileId, variantId = badVariantId,
                )
            }
        }
    }

    /**
     * `index`/`counter` is caller-supplied on both public streaming entry
     * points - a Phase 2 uploader or player drives it directly - so an
     * out-of-range value (negative, or past the 32-bit counter [buildNonce]
     * encodes) must be a catchable [CryptoError.InvalidInput], never a crash.
     * This is the Android side of the guard; iOS mirrors it in a private
     * `nonce(forIndex:isFinal:noncePrefix:)` helper because its `buildNonce`
     * takes `UInt32` directly, where a bare `UInt32(index)` conversion would
     * otherwise trap on the same inputs.
     */
    @Test
    fun encryptChunkRejectsOutOfRangeIndex() {
        val stream = Vectors.section("stream")
        val c = Vectors.objects(stream.getJSONArray("cases")).first()
        val fileId = unhex(stream.getString("file_id_hex"))
        val key = unhex(c.getString("key_hex"))
        val prefix = unhex(c.getString("nonce_prefix_hex"))
        val variantId = c.getInt("variant_id")
        for (badIndex in listOf(-1L, 0x1_0000_0000L)) {
            assertFailsWith<CryptoError.InvalidInput>("index $badIndex must be rejected") {
                cs.encryptChunk(
                    plaintext = ByteArray(4),
                    index = badIndex, isFinal = true,
                    key = key, noncePrefix = prefix, fileId = fileId, variantId = variantId,
                )
            }
        }
        // The top of the range is INCLUSIVE. Pinned here as well as in
        // nonceLayoutMatchesFixture so the two platforms cannot drift on the
        // largest legal counter: iOS enforces the range in a private helper
        // that its nonce-layout test bypasses, so this assertion is its only
        // guard against an off-by-one, and the pair must stay symmetric.
        cs.encryptChunk(
            plaintext = ByteArray(4),
            index = 0xFFFF_FFFFL, isFinal = true,
            key = key, noncePrefix = prefix, fileId = fileId, variantId = variantId,
        )
    }

    /**
     * `seal`/`open` reach the raw AEAD call with whatever nonce `buildNonce`
     * built for them. That is sound today - `buildNonce` always emits
     * exactly [WireConstants.NONCE_BYTES] bytes - but every public entry
     * point routes through `buildNonce` before calling these, so there is no
     * way to reach the guard through [encryptChunk]/[decryptChunk] with a
     * malformed nonce; `buildNonce` itself would reject a wrong-sized prefix
     * first. `seal`/`open` are `internal`, not `private`, specifically so
     * this test can call them directly and pin that they no longer take the
     * nonce length on trust, matching the existing [WireConstants.KEY_BYTES]
     * guard for key arguments.
     */
    @Test
    fun sealAndOpenRejectWrongSizedNonce() {
        val stream = Vectors.section("stream")
        val c = Vectors.objects(stream.getJSONArray("cases")).first()
        val fileId = unhex(stream.getString("file_id_hex"))
        val key = unhex(c.getString("key_hex"))
        val aad = cs.buildAad(fileId, c.getInt("variant_id"))
        val wrongNonce = ByteArray(WireConstants.NONCE_BYTES - 1)

        assertFailsWith<CryptoError.InvalidNonceLength>("seal must reject a wrong-sized nonce") {
            cs.seal(ByteArray(4), aad, wrongNonce, key)
        }

        val chunk = unhex(c.getJSONArray("chunks_hex").getString(0))
        assertFailsWith<CryptoError.InvalidNonceLength>("open must reject a wrong-sized nonce") {
            cs.open(chunk, aad, wrongNonce, key)
        }
    }

    @Test
    fun decryptChunkRejectsOutOfRangeIndex() {
        val stream = Vectors.section("stream")
        val c = Vectors.objects(stream.getJSONArray("cases")).first()
        val fileId = unhex(stream.getString("file_id_hex"))
        val key = unhex(c.getString("key_hex"))
        val prefix = unhex(c.getString("nonce_prefix_hex"))
        val variantId = c.getInt("variant_id")
        val chunk = unhex(c.getJSONArray("chunks_hex").getString(0))
        for (badIndex in listOf(-1L, 0x1_0000_0000L)) {
            assertFailsWith<CryptoError.InvalidInput>("index $badIndex must be rejected") {
                cs.decryptChunk(
                    chunk = chunk,
                    index = badIndex, isFinal = true,
                    key = key, noncePrefix = prefix, fileId = fileId, variantId = variantId,
                )
            }
        }
    }
}
