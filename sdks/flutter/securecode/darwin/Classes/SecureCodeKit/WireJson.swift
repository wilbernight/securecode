import Foundation

/// Error carrying a user-presentable message (the Swift analog of
/// Python's SerialFormatError / SignatureError distinction is handled
/// by error subtypes below).
public struct SecureCodeError: Error, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

/// Valid structure, but the Ed25519 signature does not verify.
public struct SignatureError: Error, CustomStringConvertible {
    public let message: String
    public init(_ message: String = "signature mismatch") { self.message = message }
    public var description: String { message }
}

/// Wire-format JSON: canonical (signing) serializer byte-compatible with
/// Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"),
/// ensure_ascii=True)` — the exact bytes the protector signs — plus a
/// Foundation-based parser for untrusted input (clients only parse, never
/// re-canonicalize).
///
/// Verified against sdks/vectors.json, including Persian/CJK strings, DEL,
/// control characters and astral-plane (surrogate-pair) characters.
enum WireJson {

    // ---------------------------------------------------------------- parse
    /// Parse JSON into [String: Any]/[Any]/String/NSNumber/Bool/NSNull.
    /// Duplicate keys: Foundation keeps the last one (same as Python).
    static func parse(_ text: String) throws -> Any {
        guard let data = text.data(using: .utf8) else {
            throw SecureCodeError("payload is not UTF-8")
        }
        do {
            return try JSONSerialization.jsonObject(with: data, options: [])
        } catch {
            throw SecureCodeError("payload is not JSON: \(error.localizedDescription)")
        }
    }

    static func parseObject(_ text: String) throws -> [String: Any] {
        let value = try parse(text)
        guard let obj = value as? [String: Any] else {
            throw SecureCodeError("payload is not a JSON object")
        }
        return obj
    }

    // ------------------------------------------------------------ serialize
    /// Canonical signing form (sorted keys, compact separators, ASCII-only
    /// output). Supports String / Bool / Int / Int64 / UInt64 / [String: Any]
    /// / [Any] / NSNull. Floats are rejected — the wire format never
    /// contains them.
    static func canonicalBytes(_ value: Any) throws -> [UInt8] {
        var out = ""
        try serialize(&out, value)
        return Array(out.data(using: .ascii) ?? Data())
    }

    /// Human-readable indent-2 form for local export files (parsed, never
    /// signed — mirrors Python json.dumps(indent=2)).
    static func prettyPrint(_ value: Any) throws -> String {
        guard JSONSerialization.isValidJSONObject(value) else {
            // our own types are all bridged-serializable except Date/URL —
            // fall back to the canonical writer if Foundation refuses
            return try { var s = ""; try pretty(&s, value, 0); return s }()
        }
        let data = try JSONSerialization.data(withJSONObject: value,
                                              options: [.prettyPrinted, .sortedKeys])
        return String(data: data, encoding: .utf8) ?? ""
    }

    // ---------------------------------------------------------- serializer
    private static func serialize(_ out: inout String, _ value: Any) throws {
        switch value {
        case is NSNull: out += "null"
        case let b as Bool: out += b ? "true" : "false"
        case let n as Int: out += String(n)
        case let n as Int64: out += String(n)
        case let n as UInt64: out += String(n)
        case let s as String: escape(into: &out, s)
        case let dict as [String: Any]:
            out += "{"
            let keys = dict.keys.sorted { a, b in
                Array(a.utf8).lexicographicallyPrecedes(Array(b.utf8))
                // UTF-8 byte order == Unicode code-point order — exactly
                // how Python sorts str keys (NOT Swift's default
                // canonical-equivalence comparison).
            }
            for (i, key) in keys.enumerated() {
                if i > 0 { out += "," }
                escape(into: &out, key)
                out += ":"
                try serialize(&out, dict[key]!)
            }
            out += "}"
        case let list as [Any]:
            out += "["
            for (i, item) in list.enumerated() {
                if i > 0 { out += "," }
                try serialize(&out, item)
            }
            out += "]"
        default:
            throw SecureCodeError(
                "unsupported wire type \(Swift.type(of: value))")
        }
    }

    /// Python json.dumps escaping with ensure_ascii=true: everything
    /// outside U+0020..U+007E plus '"' and '\\' is escaped; short forms for
    /// \b \t \n \f \r; lowercase-hex \uXXXX; astral characters become
    /// surrogate pairs (UTF-16 code-unit iteration makes that automatic).
    private static func escape(into out: inout String, _ s: String) {
        out += "\""
        for unit in s.utf16 {
            switch unit {
            case 0x22: out += "\\\""
            case 0x5C: out += "\\\\"
            case 0x0A: out += "\\n"
            case 0x0D: out += "\\r"
            case 0x09: out += "\\t"
            case 0x08: out += "\\b"
            case 0x0C: out += "\\f"
            case 0x20...0x7E:
                if let scalar = UnicodeScalar(unit) { out += String(scalar) }
            default:
                out += String(format: "\\u%04x", Int(unit)) // lowercase hex
            }
        }
        out += "\""
    }

    private static func pretty(_ out: inout String, _ value: Any, _ depth: Int) throws {
        let pad = String(repeating: "  ", count: depth)
        let padIn = String(repeating: "  ", count: depth + 1)
        switch value {
        case let dict as [String: Any]:
            if dict.isEmpty { out += "{}"; return }
            out += "{\n"
            let keys = dict.keys.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
            for (i, key) in keys.enumerated() {
                out += padIn
                escape(into: &out, key)
                out += ": "
                try pretty(&out, dict[key]!, depth + 1)
                out += i == keys.count - 1 ? "\n" : ",\n"
            }
            out += pad + "}"
        case let list as [Any]:
            if list.isEmpty { out += "[]"; return }
            out += "[\n"
            for (i, item) in list.enumerated() {
                out += padIn
                try pretty(&out, item, depth + 1)
                out += i == list.count - 1 ? "\n" : ",\n"
            }
            out += pad + "]"
        default:
            try serialize(&out, value)
        }
    }
}
