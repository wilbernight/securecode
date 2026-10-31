import Foundation
import CryptoKit

/// Hardware-fingerprint digest — the contract behind the machine code
/// "XXXX-XXXX-XXXX-XXXX" (mirrors shared/payload_schema.py EXACTLY):
///
///     material = mask_byte(1B) || SHA256( salt || "cpu=<v>;" || "board=<v>;"
///                                     || "disk=<v>;" || "guid=<v>;"
///                                     || "mask=<n>" )[:9]
///     code     = Base32(material) -> 16 chars, displayed 4x4
///
/// The four slot names are platform-stable hash labels: every platform SDK
/// maps ITS identifiers into the same slots (macOS: platform serial / UUID
/// / en0 MAC; iOS: Keychain UUID / IDFV).
enum FingerprintDigest {

    static let salt: [UInt8] = Array(("Secure" + "Code" + "-v1.0" + "/fp-salt")
        .data(using: .ascii)!)

    static let componentOrder = ["cpu", "board", "disk", "guid"]

    static let componentMaskBits: [String: Int] = [
        "cpu": 0x01, "board": 0x02, "disk": 0x04, "guid": 0x08,
    ]

    /// Mirrors shared.payload_schema.normalize_component: strip whitespace,
    /// strip trailing NULs (old BIOS serials), strip again, lowercase.
    static func normalizeComponent(_ value: String?) -> String {
        guard let v = value, !v.isEmpty else { return "" }
        return v.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\u{0}"))
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    /// Compute (mask, 10-byte material) for a raw component mapping.
    /// Missing/empty components contribute an empty string and clear their
    /// mask bit — the tolerance mechanism relies on this.
    static func compute(_ components: [String: String]) -> (mask: Int, material: [UInt8]) {
        var d = SHA256()
        var mask = 0
        d.update(data: Data(salt))
        for name in componentOrder {
            let norm = normalizeComponent(components[name])
            if !norm.isEmpty { mask |= (componentMaskBits[name] ?? 0) }
            d.update(data: Data("\(name)=\(norm);".data(using: .utf8) ?? Data()))
        }
        d.update(data: Data("mask=\(mask)".data(using: .ascii) ?? Data()))
        let digest = Array(d.finalize())
        var material = [UInt8(mask)]
        material.append(contentsOf: digest.prefix(9))
        return (mask, material)
    }

    /// Which components are present, decoded from a mask byte.
    static func parseComponentMask(_ mask: Int) -> [String: Bool] {
        var out: [String: Bool] = [:]
        for name in componentOrder {
            out[name] = (mask & (componentMaskBits[name] ?? 0)) != 0
        }
        return out
    }

    /// Full display machine code (4-char groups).
    static func materialCode(_ material: [UInt8]) -> String {
        SCBase32.groupBlocks(SCBase32.encode(material), size: 4)
    }
}
