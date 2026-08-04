import Foundation
import Clibsodium

/// STREAM (Rogaway et al.) over XChaCha20-Poly1305.
///
/// This module uses Clibsodium directly rather than the Sodium wrapper, and
/// that is forced, not stylistic: swift-sodium's
/// `aead.xchacha20poly1305ietf.encrypt` generates its own nonce and offers no
/// explicit-nonce overload, while STREAM requires the nonce to be constructed
/// as prefix||counter||finalFlag.
///
/// STREAM rather than libsodium's crypto_secretstream because secretstream
/// chains state between chunks, making decryption strictly sequential: seeking
/// to 40 minutes of video would mean decrypting the preceding 40 minutes. Here
/// every chunk decrypts independently, while the counter and final flag still
/// give reordering and truncation detection.
public enum ContentStream {

    /// nonce = prefix(19) || counter(4, big-endian) || finalFlag(1)
    public static func buildNonce(prefix: [UInt8], counter: UInt32, isFinal: Bool) throws -> [UInt8] {
        guard prefix.count == MantelCryptoConstants.noncePrefixBytes else {
            throw CryptoError.invalidNonceLength(
                expected: MantelCryptoConstants.noncePrefixBytes, got: prefix.count)
        }
        var n = prefix
        n.append(UInt8((counter >> 24) & 0xff))
        n.append(UInt8((counter >> 16) & 0xff))
        n.append(UInt8((counter >> 8) & 0xff))
        n.append(UInt8(counter & 0xff))
        n.append(isFinal ? 0x01 : 0x00)
        return n
    }

    /// aad = fileId(16) || variantId(1). Binds each chunk to its file AND its
    /// variant, so a chunk cannot be spliced in from another file or another
    /// variant of the same file.
    public static func buildAAD(fileId: [UInt8], variantId: UInt8) throws -> [UInt8] {
        guard fileId.count == 16 else {
            throw CryptoError.invalidInput("fileId must be 16 bytes, got \(fileId.count)")
        }
        // Must stay in lockstep with PasswordKDF.deriveVariantKey's range
        // check: that function restricts variantId to 1...3, and if this one
        // did not, an iOS client could encrypt+upload with variantId 0 or 4
        // without complaint while every Android family member throws on
        // decrypt - undecryptable data at rest, silent on the writing side.
        guard (MantelCryptoConstants.variantThumb...MantelCryptoConstants.variantOriginal).contains(variantId) else {
            throw CryptoError.invalidInput(
                "variantId must be \(MantelCryptoConstants.variantThumb)...\(MantelCryptoConstants.variantOriginal), got \(variantId)")
        }
        return fileId + [variantId]
    }

    /// Encrypt one variant of one file.
    ///
    /// `key` MUST be `PasswordKDF.deriveVariantKey(fileKey:variantId:)`. It
    /// MUST NOT be the raw file key. `noncePrefix` MUST be 19 freshly random
    /// bytes generated per (file, variant) and MUST NOT be shared with any
    /// other variant of the same file.
    ///
    /// Reusing either across variants is a plaintext-recovering two-time
    /// pad: same key + same prefix means the same keystream, so
    /// `thumb XOR preview` cancels the keystream and leaks
    /// `plaintext XOR plaintext`. AEAD authenticity does nothing about this
    /// - confidentiality is already gone. This is the v1 defect this
    /// rewrite exists to remove, and it is prevented here only by caller
    /// discipline: nothing in this signature can tell a variant subkey from
    /// a file key.
    ///
    /// The same applies to RE-ENCRYPTION, not just to sibling variants. Spec
    /// §11 stores `noncePrefix{thumb,preview,original}` per photo, so a
    /// Phase 2 "re-upload after rotate/edit" path that reads the stored
    /// prefix back and re-encrypts with an unchanged file key produces the
    /// identical keystream over new plaintext - the same two-time pad by
    /// another route. Re-encrypting means a fresh prefix (and, better, a
    /// fresh file key), never the stored one.
    public static func encrypt(plaintext: [UInt8], key: [UInt8], noncePrefix: [UInt8],
                               fileId: [UInt8], variantId: UInt8,
                               chunkSize: Int = MantelCryptoConstants.chunkSize) throws -> [[UInt8]] {
        try validateKey(key)
        guard chunkSize > 0 else { throw CryptoError.invalidInput("chunkSize must be positive") }

        // Zero-length plaintext still yields ONE authenticated chunk, so
        // decryption has something to verify rather than accepting nothing.
        let total = max(1, Int((plaintext.count + chunkSize - 1) / chunkSize))
        var out = [[UInt8]]()
        out.reserveCapacity(total)
        for i in 0..<total {
            let lo = i * chunkSize
            let hi = min(lo + chunkSize, plaintext.count)
            let slice = lo < hi ? Array(plaintext[lo..<hi]) : []
            out.append(try encryptChunk(slice, index: i, isFinal: i == total - 1,
                                        key: key, noncePrefix: noncePrefix,
                                        fileId: fileId, variantId: variantId))
        }
        return out
    }

    /// Encrypt one chunk in isolation - the streaming counterpart to
    /// `decryptChunk`, and what lets a caller encrypt a multi-gigabyte video
    /// without holding the whole thing (or even a whole variant) in memory at
    /// once. `encrypt` is now just this, called in a loop.
    ///
    /// `key` MUST be `PasswordKDF.deriveVariantKey(fileKey:variantId:)`,
    /// never the raw file key, and `noncePrefix` MUST be fresh per (file,
    /// variant). See `encrypt`'s doc comment for why: reusing either is a
    /// plaintext-recovering two-time pad, and nothing in this signature can
    /// tell a variant subkey from a file key - that discipline is entirely on
    /// the caller.
    ///
    /// Calling this directly also moves two guarantees `encrypt` used to give
    /// you onto the caller:
    ///
    /// - Final-flag discipline: exactly one chunk - the last one - must be
    ///   encrypted with `isFinal = true`. Getting this wrong produces a
    ///   stream that `decrypt` will reject outright, which is the safe
    ///   direction to fail in, but it will not encrypt to anything `decrypt`
    ///   accepts.
    /// - Truncation detection: it lives entirely in `decrypt`'s
    ///   position-derived `isFinal` flag on the read side. A caller that
    ///   assembles chunks itself (e.g. uploading each chunk as an S3
    ///   multipart part) gets per-chunk authenticity from this function, but
    ///   NOT stream-level truncation detection unless it also independently
    ///   records and checks the chunk count. `decryptChunk`'s doc comment
    ///   carries the mirror of this caveat on the read side.
    public static func encryptChunk(_ plaintext: [UInt8], index: Int, isFinal: Bool,
                                    key: [UInt8], noncePrefix: [UInt8],
                                    fileId: [UInt8], variantId: UInt8) throws -> [UInt8] {
        try validateKey(key)
        let aad = try buildAAD(fileId: fileId, variantId: variantId)
        let n = try nonce(forIndex: index, isFinal: isFinal, noncePrefix: noncePrefix)
        return try seal(plaintext, aad: aad, nonce: n, key: key)
    }

    public static func decrypt(chunks: [[UInt8]], key: [UInt8], noncePrefix: [UInt8],
                               fileId: [UInt8], variantId: UInt8) throws -> [UInt8] {
        try validateKey(key)
        guard !chunks.isEmpty else { throw CryptoError.emptyStream }
        var out = [UInt8]()
        for (i, chunk) in chunks.enumerated() {
            out += try decryptChunk(chunk, index: i, isFinal: i == chunks.count - 1,
                                    key: key, noncePrefix: noncePrefix,
                                    fileId: fileId, variantId: variantId)
        }
        return out
    }

    /// Decrypt one chunk in isolation - this is what makes video seeking work.
    ///
    /// Truncation detection lives entirely in `decrypt`'s position-derived
    /// `isFinal` flag: a random-access/seeking caller that only ever invokes
    /// this with `isFinal = false` gets chunk-level authenticity but NOT
    /// truncation detection for the stream as a whole.
    public static func decryptChunk(_ chunk: [UInt8], index: Int, isFinal: Bool,
                                    key: [UInt8], noncePrefix: [UInt8],
                                    fileId: [UInt8], variantId: UInt8) throws -> [UInt8] {
        try validateKey(key)
        let aad = try buildAAD(fileId: fileId, variantId: variantId)
        let n = try nonce(forIndex: index, isFinal: isFinal, noncePrefix: noncePrefix)
        return try open(chunk, aad: aad, nonce: n, key: key)
    }

    /// `buildNonce` takes `counter: UInt32`, so a bare `UInt32(index)` at a
    /// call site is a TRAPPING conversion: `UInt32(-1)` or `UInt32(1 <<
    /// 40)` crashes the process (SIGTRAP) rather than throwing. `index` is
    /// caller-supplied - `encryptChunk`/`decryptChunk` are public entry
    /// points built specifically for a Phase 2 uploader/player to drive the
    /// index itself - so a loop-counter bug or a wrongly-computed
    /// resumed-upload offset must be a catchable `CryptoError`, matching
    /// Android's `Long`-typed `counter` and its range guard in
    /// `buildNonce`, not an uncatchable crash.
    private static func nonce(forIndex index: Int, isFinal: Bool, noncePrefix: [UInt8]) throws -> [UInt8] {
        guard index >= 0 && index <= Int(UInt32.max) else {
            throw CryptoError.invalidInput("counter out of range: \(index)")
        }
        return try buildNonce(prefix: noncePrefix, counter: UInt32(index), isFinal: isFinal)
    }

    /// Shared by every entry point that reaches the raw Clibsodium calls
    /// below. `open`/`seal` pass `key` straight into
    /// `crypto_aead_xchacha20poly1305_ietf_{en,de}crypt`, which reads 32
    /// bytes from it unconditionally - a short array is a read past the end
    /// of Swift-owned storage, and a long one silently succeeds using only
    /// its first 32 bytes.
    private static func validateKey(_ key: [UInt8]) throws {
        guard key.count == MantelCryptoConstants.keyBytes else {
            throw CryptoError.invalidKeyLength(expected: MantelCryptoConstants.keyBytes, got: key.count)
        }
    }

    // MARK: - Clibsodium

    // Not `private`: every production path reaches this nonce via
    // buildNonce (which itself always emits MantelCryptoConstants.nonceBytes),
    // so there is no way to drive a wrong-sized nonce here through the
    // public API - the assertion below can only be exercised directly, from
    // ContentStreamTests via `@testable import`, which sees `internal` but
    // not `private` declarations.
    static func seal(_ message: [UInt8], aad: [UInt8], nonce: [UInt8], key: [UInt8]) throws -> [UInt8] {
        // Every path here reaches this nonce via buildNonce, which enforces
        // the 19-byte prefix and appends exactly 5 fixed bytes - so today
        // this can only ever be 24 bytes. But that is an inference about all
        // current callers, not something this function enforces on its own,
        // and unlike Android's lazysodium call, this hands the nonce straight
        // to a raw Clibsodium call, which reads nonceBytes from it
        // unconditionally: a short array is a read past the end of
        // Swift-owned storage, not a graceful failure. Asserting here means
        // buildNonce is the only thing that has to be right (mirrors
        // validateKey's role for key arguments, just below).
        guard nonce.count == MantelCryptoConstants.nonceBytes else {
            throw CryptoError.invalidNonceLength(expected: MantelCryptoConstants.nonceBytes, got: nonce.count)
        }
        var ct = [UInt8](repeating: 0, count: message.count + MantelCryptoConstants.tagBytes)
        var ctLen: UInt64 = 0
        let rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
            &ct, &ctLen,
            message, UInt64(message.count),
            aad, UInt64(aad.count),
            nil, nonce, key)
        guard rc == 0 else { throw CryptoError.invalidInput("AEAD encrypt failed") }
        return Array(ct[0..<Int(ctLen)])
    }

    // Not `private`: see seal()'s matching comment above.
    static func open(_ ciphertext: [UInt8], aad: [UInt8], nonce: [UInt8], key: [UInt8]) throws -> [UInt8] {
        // See seal()'s matching comment: buildNonce is the only thing that
        // has to be right for this to always be nonceBytes, and this asserts
        // that instead of merely inferring it before handing the nonce to
        // the raw Clibsodium call below.
        guard nonce.count == MantelCryptoConstants.nonceBytes else {
            throw CryptoError.invalidNonceLength(expected: MantelCryptoConstants.nonceBytes, got: nonce.count)
        }
        // DELIBERATE EXCEPTION - do not tighten to `>` like KeyBox.open and
        // IdentityBox.openShare: a bare 16-byte tag-only chunk is the
        // legitimate encoding of an empty-plaintext STREAM chunk (see
        // encrypt() above - a zero-length plaintext still yields one
        // authenticated chunk so decryption has something to verify). Unlike
        // KeyBox/IdentityBox, an empty RESULT here is a valid outcome, not a
        // sign of a malformed input, so `>=` must stay.
        guard ciphertext.count >= MantelCryptoConstants.tagBytes else {
            throw CryptoError.invalidInput("chunk shorter than the authentication tag")
        }
        var pt = [UInt8](repeating: 0, count: ciphertext.count - MantelCryptoConstants.tagBytes)
        var ptLen: UInt64 = 0
        let rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
            &pt, &ptLen, nil,
            ciphertext, UInt64(ciphertext.count),
            aad, UInt64(aad.count),
            nonce, key)
        // rc != 0 covers every rejection we care about: wrong counter
        // (reordering), wrong final flag (truncation), wrong fileId or
        // variantId (splicing), and tampered bytes.
        guard rc == 0 else { throw CryptoError.authenticationFailed }
        return Array(pt[0..<Int(ptLen)])
    }
}
