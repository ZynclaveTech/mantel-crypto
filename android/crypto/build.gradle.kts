// Pure Kotlin JVM module, deliberately NOT an Android library module.
//
// The crypto core has no Android dependencies, so its tests run on a plain
// host JVM in milliseconds with no emulator. lazysodium ships Android-only
// native libraries that a host JVM cannot load, which is why every class here
// takes a LazySodium instance by constructor injection: tests inject
// LazySodiumJava, and the app will inject LazySodiumAndroid in Phase 2.
plugins {
    id("org.jetbrains.kotlin.jvm")
}

kotlin { jvmToolchain(21) }

dependencies {
    // compileOnly, not implementation: the app supplies lazysodium-android at
    // runtime, and having both artifacts on one classpath risks duplicate
    // classes (the android aar bundles the java classes).
    compileOnly("com.goterl:lazysodium-java:5.2.0")

    // lazysodium-java's Gradle module metadata only puts jna on its
    // runtimeElements variant, not apiElements - so it never lands on this
    // module's main compile classpath, even though PasswordKdf needs
    // com.sun.jna.NativeLong for Argon2id's memlimit argument. Without this,
    // :crypto:compileKotlin fails with "Unresolved reference 'NativeLong'".
    // compileOnly for the same reason as lazysodium-java above: the app
    // supplies lazysodium-android (which bundles JNA) at runtime.
    compileOnly("net.java.dev.jna:jna:5.19.1")

    testImplementation("com.goterl:lazysodium-java:5.2.0")
    testImplementation("net.java.dev.jna:jna:5.19.1")
    testImplementation("org.json:json:20260719")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "failed") }
}
