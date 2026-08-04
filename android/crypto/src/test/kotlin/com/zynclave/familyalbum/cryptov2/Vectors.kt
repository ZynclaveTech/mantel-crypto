package com.zynclave.familyalbum.cryptov2

import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import java.io.File
import org.json.JSONArray
import org.json.JSONObject

/**
 * Loads the shared test-vector fixture produced by the Node reference
 * implementation at `tools/vectors/`.
 *
 * The fixture is the CONTRACT: this module must reproduce it byte for byte.
 * It is READ-ONLY here and no test may ever write to it. The protocol this
 * replaces generated its vectors FROM the iOS test suite, which made iOS the
 * oracle - so an iOS bug became the specification and Android faithfully
 * conformed to it.
 */
object Vectors {

    /**
     * Walks up from the Gradle module directory to the repository root.
     * Gradle runs tests with the module dir as the working directory, so
     * `android/crypto` -> `android` -> repo root.
     */
    private val fixture: File by lazy {
        var dir = File(System.getProperty("user.dir")).absoluteFile
        while (dir.parentFile != null && !File(dir, "tools/vectors/vectors.json").exists()) {
            dir = dir.parentFile
        }
        File(dir, "tools/vectors/vectors.json").also {
            check(it.exists()) { "could not locate tools/vectors/vectors.json from ${System.getProperty("user.dir")}" }
        }
    }

    fun load(): JSONObject = JSONObject(fixture.readText())

    fun section(name: String): JSONObject = load().getJSONObject(name)

    fun array(name: String): List<JSONObject> {
        val a: JSONArray = load().getJSONArray(name)
        return (0 until a.length()).map { a.getJSONObject(it) }
    }

    fun objects(a: JSONArray): List<JSONObject> = (0 until a.length()).map { a.getJSONObject(it) }
}

/** Shared host-JVM sodium instance for tests. */
val testSodium: LazySodium by lazy { LazySodiumJava(SodiumJava()) }

fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

fun unhex(s: String): ByteArray =
    ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
