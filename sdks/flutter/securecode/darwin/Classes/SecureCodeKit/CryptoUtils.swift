import Foundation
import CryptoKit

/// Machine-bound key derivation + symmetric crypto (mirrors
/// target_demo/protection/crypto_utils.py):
///
///     HKDF-SHA256( ikm  = embedded_master_secret || "|" || machine_code,
///                  salt = product_id,  info = purpose_context )
///
/// The machine code participates in the IKM, so artifacts are bound to the
/// device: copying license.dat to another Mac/iPhone fails AES-GCM
/// authentication before any license logic runs. The master secret lives
/// only in the obfuscated string layer (SecureStrings — regenerate per
/// product with sdks/gen_strings.py).
///
/// Note: HKDF is implemented manually (RFC 5869) because CryptoKit's HKDF
/// requires iOS 14+; the kit targets iOS 13.
enum CryptoUtils {

    // ---------------------------------------------------------------- HKDF
    /// RFC 5869 HKDF-SHA256 (extract + expand) — matches the reference
    /// vectors and Python's `cryptography` HKDF byte-for-byte.
    static func hkdfSHA256(ikm: [UInt8], salt: [UInt8], info: [UInt8],
                           length: Int) -> [UInt8] {
        // extract
        let prk = Array(HMAC<SHA256>.authenticationCode(
            for: Data(ikm), using: SymmetricKey(data: Data(salt))))
        // expand
        var out = [UInt8]()
        out.reserveCapacity(length)
        var t = [UInt8]()
        var counter: UInt8 = 1
        while out.count < length {
            var hmac = HMAC<SHA256>()
            hmac.update(data: Data(t))
            hmac.update(data: Data(info))
            hmac.update(data: Data([counter]))
            let block = Array(hmac.finalize(with: SymmetricKey(data: Data(prk))))
            let need = length - out.count
            out.append(contentsOf: block.prefix(need))
            t = block
            counter &+= 1
        }
        return out
    }

    /// Purpose-bound machine key — identical construction to the Windows
    /// client (crypto_utils.derive_machine_key).
    static func deriveMachineKey(master: [UInt8], machineCode: String,
                                 productId: String, context: String) -> [UInt8] {
        var ikm = master
        ikm.append(contentsOf: Array("|".data(using: .ascii)!))
        ikm.append(contentsOf: Array(machineCode.data(using: .ascii)!))
        return hkdfSHA256(ikm: ikm,
                          salt: Array(productId.data(using: .ascii)!),
                          info: Array(context.data(using: .utf8)!),
                          length: 32)
    }

    // ------------------------------------------------------------- AES-GCM
    /// AES-256-GCM with a fresh random 12-byte nonce prepended.
    static func gcmEncrypt(key: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
        let sealed = try AES.GCM.seal(Data(plaintext),
                                      using: SymmetricKey(data: Data(key)))
        guard let combined = sealed.combined else {
            throw SecureCodeError("GCM seal produced no combined representation")
        }
        return Array(combined)
    }

    /// Inverse of gcmEncrypt; throws on any authentication failure.
    static func gcmDecrypt(key: [UInt8], blob: [UInt8]) throws -> [UInt8] {
        guard blob.count > 12 + 16 else {
            throw SecureCodeError("ciphertext too short")
        }
        do {
            let box = try AES.GCM.SealedBox(combined: Data(blob))
            return try Array(AES.GCM.open(box, using: SymmetricKey(data: Data(key))))
        } catch {
            throw SecureCodeError("decryption failed (tampered or wrong key)")
        }
    }

    // ----------------------------------------------------------- utilities
    static func packU64(_ value: UInt64) -> [UInt8] {
        withUnsafeBytes(of: value.bigEndian) { Array($0) }
    }

    static func unpackU64(_ data: [UInt8]) -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<8 { v = (v << 8) | UInt64(data[i]) }
        return v
    }

    static func sha256(_ data: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(data)))
    }

    static func toHex(_ data: [UInt8]) -> String {
        data.map { String(format: "%02x", Int($0)) }.joined()
    }

    static func fromHex(_ hex: String) -> [UInt8] {
        var chars = Array(hex)
        if chars.count % 2 == 1 { chars.insert("0", at: 0) }
        var out = [UInt8]()
        out.reserveCapacity(chars.count / 2)
        var i = 0
        while i + 1 < chars.count {
            let hi = hexDigit(chars[i])
            let lo = hexDigit(chars[i + 1])
            if hi < 0 || lo < 0 { break }
            out.append(UInt8(truncatingIfNeeded: hi << 4 | lo))
            i += 2
        }
        return out
    }

    private static func hexDigit(_ c: Character) -> Int {
        if let d = c.wholeNumberValue, d >= 0, d <= 9 { return d }
        switch c {
        case "a", "A": return 10
        case "b", "B": return 11
        case "c", "C": return 12
        case "d", "D": return 13
        case "e", "E": return 14
        case "f", "F": return 15
        default: return -1
        }
    }
}
