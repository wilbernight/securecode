import Foundation

/// The signed body of a serial key (mirrors shared.payload_schema.
/// LicensePayload — same field names, same validation, byte-identical
/// canonical serialization).
public struct LicensePayload: Equatable {

    public let fingerprint: String        // machine code "XXXX-XXXX-XXXX-XXXX"
    public let productId: String          // product UUID string (lowercase)
    public let issuedAt: Int64            // unix ts (seconds)
    public let expiresAt: Int64           // unix ts; 0 = lifetime
    public let customer: String           // free-form customer name/ID
    public let nonce: String              // 16-byte hex; uniqueness + revocation id
    public let featureFlags: [String: Bool]
    public let tolerance: Int             // missing fingerprint components allowed
    public let rollbackAllowance: Int     // clock rollbacks tolerated
    public let version: Int

    public init(fingerprint: String, productId: String, issuedAt: Int64,
                expiresAt: Int64, customer: String = "", nonce: String = "",
                featureFlags: [String: Bool] = [:], tolerance: Int = 1,
                rollbackAllowance: Int = 3, version: Int = LicensePayload.payloadVersion) {
        self.fingerprint = fingerprint
        self.productId = productId
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.customer = customer
        self.nonce = nonce
        self.featureFlags = featureFlags
        self.tolerance = tolerance
        self.rollbackAllowance = rollbackAllowance
        self.version = version
        try! validate() // keep initializers non-throwing; misuse is a programmer error
    }

    public var isLifetime: Bool { expiresAt == LicensePayload.expLifetime }

    public func secondsLeft(now: Int64? = nil) -> Int64 {
        let n = now ?? Int64(Date().timeIntervalSince1970)
        return isLifetime ? LicensePayload.maxTimestamp - n : expiresAt - n
    }

    // ------------------------------------------------------------ wire form
    public func toWire() -> [String: Any] {
        [
            "v": version,
            "fp": fingerprint,
            "pid": productId,
            "iat": issuedAt,
            "exp": expiresAt,
            "cust": customer,
            "n": nonce,
            "fl": featureFlags,
            "tol": tolerance,
            "rb": rollbackAllowance,
        ]
    }

    /// Byte-exact canonical JSON (what the protector signed).
    public func canonicalBytes() throws -> [UInt8] {
        try WireJson.canonicalBytes(toWire())
    }

    // ------------------------------------------------------------ parse
    static func fromWire(_ data: [String: Any]) throws -> LicensePayload {
        func req(_ key: String) throws -> Any {
            guard let v = data[key] else {
                throw SecureCodeError("payload missing required field: '\(key)'")
            }
            return v
        }
        func asInt64(_ key: String, _ v: Any?) throws -> Int64? {
            guard let v = v else { return nil }
            if let n = v as? Int64 { return n }
            if let n = v as? Int { return Int64(n) }
            if let n = v as? NSNumber { return n.int64Value }
            if let s = v as? String, let n = Int64(s) { return n }
            throw SecureCodeError("payload field '\(key)' has invalid type")
        }
        var flags: [String: Bool] = [:]
        if let fl = data["fl"] as? [String: Any] {
            for (k, v) in fl { flags[k] = pythonTruth(v) }
        }
        let payload = LicensePayload(
            fingerprint: "\(try req("fp"))",
            productId: "\(try req("pid"))",
            issuedAt: try asInt64("iat", req("iat")) ?? 0,
            expiresAt: try asInt64("exp", req("exp")) ?? 0,
            customer: (data["cust"] as? String) ?? "",
            nonce: (data["n"] as? String) ?? "",
            featureFlags: flags,
            tolerance: Int(try asInt64("tol", data["tol"]) ?? 1),
            rollbackAllowance: Int(try asInt64("rb", data["rb"]) ?? 3),
            version: Int(try asInt64("v", req("v")) ?? 0))
        try payload.validate()
        return payload
    }

    /// Python bool() semantics for the feature-flag coercion.
    private static func pythonTruth(_ v: Any) -> Bool {
        switch v {
        case is NSNull: return false
        case let b as Bool: return b
        case let n as NSNumber: return n != 0
        case let s as String: return !s.isEmpty
        case let l as [Any]: return !l.isEmpty
        case let d as [String: Any]: return !d.isEmpty
        default: return true
        }
    }

    // ------------------------------------------------------------ validation
    func validate() throws {
        guard version == LicensePayload.payloadVersion else {
            throw SecureCodeError("unsupported payload version \(version)")
        }
        if expiresAt != LicensePayload.expLifetime {
            guard (LicensePayload.minTimestamp...LicensePayload.maxTimestamp)
                .contains(expiresAt) else {
                throw SecureCodeError("expires_at out of sane range")
            }
        }
        guard (LicensePayload.minTimestamp...LicensePayload.maxTimestamp)
            .contains(issuedAt) else {
            throw SecureCodeError("issued_at out of sane range")
        }
        if expiresAt != LicensePayload.expLifetime, expiresAt < issuedAt {
            throw SecureCodeError("expires_at before issued_at")
        }
        guard isUuid(productId) else {
            throw SecureCodeError("product_id is not a UUID")
        }
        let compact = fingerprint.replacingOccurrences(of: "-", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard compact.count == 16,
              compact.allSatisfy({ $0.isASCII && "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains($0) })
        else {
            throw SecureCodeError("fingerprint field is not a valid machine code")
        }
        if !nonce.isEmpty {
            let lower = nonce.lowercased()
            guard lower.count == 32,
                  lower.allSatisfy({ c in
                      c.isASCII && (("0"..."9").contains(c) || ("a"..."f").contains(c))
                  })
            else {
                throw SecureCodeError("nonce must be 16 bytes of hex")
            }
        }
    }

    /// Python uuid.UUID acceptance: dashed 8-4-4-4-12 or plain 32 hex.
    private func isUuid(_ value: String) -> Bool {
        let chars = Array(value)
        if chars.count == 36 {
            for (i, c) in chars.enumerated() {
                if [8, 13, 18, 23].contains(i) {
                    if c != "-" { return false }
                } else if !(c.isASCII && c.isHexDigit) {
                    return false
                }
            }
            return true
        }
        if chars.count == 32 {
            return chars.allSatisfy { $0.isASCII && $0.isHexDigit }
        }
        return false
    }
}

extension LicensePayload {
    static let payloadVersion = 1
    static let expLifetime: Int64 = 0
    static let minTimestamp: Int64 = 1_577_836_800   // 2020-01-01
    static let maxTimestamp: Int64 = 4_102_444_800   // 2100-01-01
}
