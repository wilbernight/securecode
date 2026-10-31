import Foundation

/// The signed-envelope wire format shared by serial keys, blacklists and
/// transfer permits (mirrors shared/codec.py):
///
///     artifact_text = Base32( body_bytes || Ed25519_signature(64B) )
///
/// Ed25519 signatures are fixed-length (RFC 8032), so the verifier splits
/// the LAST 64 bytes.
enum Envelope {

    static let signatureLength = 64
    static let serialGroupSize = 5

    static func encode(body: [UInt8], signature: [UInt8]) throws -> String {
        guard signature.count == signatureLength else {
            throw SecureCodeError("Ed25519 signature must be \(signatureLength) bytes")
        }
        return SCBase32.groupBlocks(
            SCBase32.encode(body + signature), size: serialGroupSize)
    }

    /// Split artifact text into (body, signature).
    /// Throws `SecureCodeError` when too short / undecodable.
    static func decode(_ text: String) throws -> ([UInt8], [UInt8]) {
        let raw = try SCBase32.decode(text)
        guard raw.count >= signatureLength else {
            throw SecureCodeError("serial is too short to contain a valid signature")
        }
        return (Array(raw.dropLast(signatureLength)),
                Array(raw.suffix(signatureLength)))
    }
}
