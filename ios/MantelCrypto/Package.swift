// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MantelCrypto",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "MantelCrypto", targets: ["MantelCrypto"]),
    ],
    dependencies: [
        // Resolves to 0.11.0. Provides Argon2id, crypto_kdf, secretbox and box.
        // Content encryption and SHA-512 go through Clibsodium, which this
        // package also vendors - see ContentStream.swift and SafetyNumber.swift.
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.1"),
    ],
    targets: [
        .target(
            name: "MantelCrypto",
            dependencies: [
                .product(name: "Sodium", package: "swift-sodium"),
                .product(name: "Clibsodium", package: "swift-sodium"),
            ]
        ),
        .testTarget(
            name: "MantelCryptoTests",
            dependencies: [
                "MantelCrypto",
                // Needed to construct a genuine tag-only ciphertext (a real
                // secretbox/box seal of empty plaintext) for the KeyBox and
                // IdentityBox tag-only-rejection tests - an arbitrary
                // all-zero 16-byte array does not authenticate, so proving
                // the guard rejects a ciphertext that WOULD otherwise
                // authenticate requires the real primitive.
                .product(name: "Sodium", package: "swift-sodium"),
            ]
        ),
    ]
)
