import Foundation
import CryptoKit

/// Ed25519 signature verification via CryptoKit (iOS 13+ / macOS 10.15+ —
/// no manual curve math needed, unlike the Android port which supports
/// API 24). Byte-compatible with OpenSSL / Python `cryptography`.
enum Ed25519 {

    /// Verify an Ed25519 signature. Returns false for ANY malformed input
    /// (never throws) — a rejected signature simply reads as invalid.
    static func verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8]) -> Bool {
        guard publicKey.count == 32, signature.count == 64 else { return false }
        do {
            let key = try Curve25519.Signing.PublicKey(rawRepresentation: Data(publicKey))
            return key.isValidSignature(Data(signature), for: Data(message))
        } catch {
            return false
        }
    }
}
