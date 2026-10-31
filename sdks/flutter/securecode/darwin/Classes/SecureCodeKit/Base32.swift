import Foundation

/// RFC 4648 Base32 codec — identical behavior to the Windows client's
/// shared/codec.py (repair heuristic included: customers sometimes swap
/// O/0 or I/1; the digits 0/1/8/9 never appear in the alphabet).
enum SCBase32 {

    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    private static let values: [Int8] = {
        var table = [Int8](repeating: -1, count: 128)
        for (i, c) in alphabet.enumerated() {
            table[Int(c.asciiValue!)] = Int8(i)
            table[Int(c.asciiValue!) + 32] = Int8(i) // lowercase
        }
        return table
    }()

    static func encode(_ data: [UInt8]) -> String {
        var out = [Character]()
        out.reserveCapacity((data.count * 8 + 4) / 5)
        var i = 0
        while i + 5 <= data.count {
            let chunk = (UInt64(data[i]) << 32) | (UInt64(data[i + 1]) << 24) |
                       (UInt64(data[i + 2]) << 16) | (UInt64(data[i + 3]) << 8) |
                       UInt64(data[i + 4])
            for shift in stride(from: 35, through: 0, by: -5) {
                out.append(alphabet[Int((chunk >> UInt64(shift)) & 0x1F)])
            }
            i += 5
        }
        let rem = data.count - i
        if rem > 0 {
            var chunk: UInt64 = 0
            for j in 0..<rem { chunk = (chunk << 8) | UInt64(data[i + j]) }
            chunk <<= UInt64((5 - rem) * 8) // align as if 5 bytes were present
            let chars = rem * 8 / 5 // 1->1, 2->3, 3->4, 4->6
            for shift in stride(from: 35, through: 0, by: -5).prefix(chars) {
                out.append(alphabet[Int((chunk >> UInt64(shift)) & 0x1F)])
            }
        }
        return String(out)
    }

    /// Decode Base32 text (any casing/spacing/dashes; strips 0/1/8/9).
    /// Throws `SecureCodeError` — never a platform-specific error.
    static func decode(_ text: String) throws -> [UInt8] {
        let compact = flattenRepair(text)
        var out = [UInt8]()
        out.reserveCapacity(compact.count * 5 / 8)
        var buffer: UInt16 = 0
        var bits = 0
        for c in compact.unicodeScalars {
            let value: Int8
            if c.isASCII, let a = c.asciiValue, Int(a) < 128 {
                value = values[Int(a)]
            } else {
                value = -1
            }
            if value < 0 {
                throw SecureCodeError("serial contains characters outside Base32 alphabet")
            }
            buffer = (buffer << 5) | UInt16(bitPattern: UInt8(truncatingIfNeeded: value))
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8(truncatingIfNeeded: buffer >> UInt16(bits)))
            }
        }
        return out
    }

    /// Uppercase + alphanumerics only + strip the digits Base32 never uses.
    static func flattenRepair(_ text: String) -> String {
        var out = ""
        out.reserveCapacity(text.count)
        for scalar in text.uppercased().unicodeScalars {
            if scalar.isLetter || scalar.isNumber {
                let c = String(scalar)
                if c != "0" && c != "1" && c != "8" && c != "9" { out += c }
            }
        }
        return out
    }

    /// Uppercase + alphanumerics only (serial/machine-code flattening).
    static func flatten(_ text: String) -> String {
        var out = ""
        out.reserveCapacity(text.count)
        for scalar in text.uppercased().unicodeScalars {
            if scalar.isLetter || scalar.isNumber { out += String(scalar) }
        }
        return out
    }

    static func groupBlocks(_ text: String, size: Int, separator: String = "-") -> String {
        guard !text.isEmpty else { return text }
        var out = ""
        var start = text.startIndex
        while start < text.endIndex {
            if start != text.startIndex { out += separator }
            let end = text.index(start, offsetBy: size, limitedBy: text.endIndex) ?? text.endIndex
            out += String(text[start..<end])
            start = end
        }
        return out
    }
}
