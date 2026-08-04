package com.zynclave.familyalbum.cryptov2

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class VectorsTest {

    @Test
    fun fixtureLoadsWithEverySection() {
        val v = Vectors.load()
        for (section in listOf("kdf", "subkeys", "keybox", "identity", "stream", "negative", "safety_number")) {
            assertTrue(v.has(section), "fixture is missing section '$section'")
        }
    }

    @Test
    fun hexRoundTrips() {
        assertEquals("00ff10", hex(unhex("00ff10")))
        assertEquals(listOf<Byte>(0, -1, 16), unhex("00ff10").toList())
    }

    @Test
    fun wireConstantsMatchSpec() {
        assertEquals(8 * 1024 * 1024, WireConstants.CHUNK_SIZE)
        assertEquals(19, WireConstants.NONCE_PREFIX_BYTES)
        assertEquals(24, WireConstants.NONCE_BYTES)
        assertEquals(16, WireConstants.TAG_BYTES)
        assertEquals(32, WireConstants.KEY_BYTES)
        assertEquals("mantelAu", WireConstants.AUTH_CONTEXT)
        assertEquals("mantelFV", WireConstants.VARIANT_CONTEXT)
        // crypto_kdf contexts are exactly 8 bytes. Wire spec.
        assertEquals(8, WireConstants.AUTH_CONTEXT.toByteArray(Charsets.UTF_8).size)
        assertEquals(8, WireConstants.VARIANT_CONTEXT.toByteArray(Charsets.UTF_8).size)
    }

    @Test
    fun fixturePathResolves() {
        // getJSONObject/getJSONArray throw rather than return null on a missing
        // key, so asserting non-null here would prove nothing (and
        // fixtureLoadsWithEverySection already covers section presence). This
        // instead confirms the loader found the real repository fixture and
        // not an empty or wrong file, by checking known fixture content.
        val stream = Vectors.section("stream")
        assertTrue(stream.getJSONArray("cases").length() > 0, "stream.cases should be non-empty")
        assertEquals(8 * 1024 * 1024, stream.getInt("production_chunk_size"))
    }
}
