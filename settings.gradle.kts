// Standalone build for the crypto core. In the Mantel app repo this module is
// one of several; here it is the whole project, so the module directory is
// mapped explicitly and the layout of the app repo is preserved otherwise.
//
// The layout is deliberate: both test suites locate tools/vectors/vectors.json
// by walking UP from their own location, so keeping ios/, android/ and tools/
// where they were means the vector tests work here unchanged rather than
// depending on edits made during extraction.
pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { mavenCentral() }
}

rootProject.name = "mantel-crypto"
include(":crypto")
project(":crypto").projectDir = file("android/crypto")
