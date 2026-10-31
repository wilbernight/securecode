import Foundation

/// Every terminal state of the local license evaluation (mirrors the
/// Windows client's LicenseState).
public enum LicenseState: String {
    case valid
    case missing            // never activated on this device
    case invalid            // signature/structure failure
    case expired
    case wrongMachine       // serial bound to a different fingerprint
    case revoked            // nonce is on the signed blacklist
    case clockTampered      // rollback beyond allowance
    case damaged            // unreadable local store
    case degraded           // silent anti-RE degrade mode active
}

/// Result of activate().
public struct ActivationResult {
    public let ok: Bool
    public let state: LicenseState
    public let message: String
    public let payload: LicensePayload?
}

/// Result of verifyInstalled().
public struct LicenseStatus {
    public let state: LicenseState
    public let message: String
    public let payload: LicensePayload?
    public let secondsLeft: Int64

    public var isValid: Bool { state == .valid }
}

/// The offline license client — a faithful port of
/// target_demo/protection/license_client.py. See that module's docstring
/// for the full activation / launch-verification / machine-transfer flow.
///
/// All methods perform small local file I/O + cryptography — call from a
/// background queue (see the platform README).
public final class LicenseClient {

    private let config: ProtectionConfig
    private let antiDebug: AntiDebug?
    private let clockGuardRef: ClockGuard?

    private var machineCodeCache: String?
    private var fileKeyCache: [UInt8]?
    private lazy var clock: ClockGuard = clockGuardRef ?? ClockGuard(config)

    private static let licenseMagic: [UInt8] = Array("SCLIC1".data(using: .ascii)!)

    /// Size caps before reading local artifacts (resource-exhaustion
    /// hardening: a dropped multi-GB file must fail fast as a clean
    /// DAMAGED/malformed state, never as an OOM crash). Real sizes: license
    /// ~2 KB, permit ~1 KB; a legit 100k-entry blacklist is ~4-5 MB.
    /// Mirrors the Python client + Android SDK.
    static let maxLicenseBytes = 1 << 20        // 1 MiB
    static let maxBlacklistBytes = 16 << 20    // 16 MiB
    static let maxPermitBytes = 1 << 20         // 1 MiB

    /// File size in bytes (0 when the stat fails — the read then fails too).
    static func fileSize(_ url: URL) -> Int {
        (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize ?? 0
    }

    /// Plain client (no runtime wiring).
    public convenience init(_ config: ProtectionConfig) {
        self.init(config, antiDebug: nil, clockGuard: nil)
    }

    /// Runtime-wired client (share the SAME client across the app).
    init(_ config: ProtectionConfig, antiDebug: AntiDebug?, clockGuard: ClockGuard?) {
        self.config = config
        self.antiDebug = antiDebug
        self.clockGuardRef = clockGuard
    }

    // ================================================================ helpers
    /// This device's machine code "XXXX-XXXX-XXXX-XXXX" (cached).
    public func machineCode() -> String {
        if let cached = machineCodeCache { return cached }
        let code = Fingerprint.machineCode(config)
        machineCodeCache = code
        return code
    }

    private func publicKey() -> [UInt8] { config.publicKey }

    private func fileKey() -> [UInt8] {
        if let cached = fileKeyCache { return cached }
        let key = CryptoUtils.deriveMachineKey(
            master: SecureStrings.bytes("license_master"),
            machineCode: machineCode(), productId: config.productId,
            context: "license-file-v1")
        fileKeyCache = key
        return key
    }

    // ================================================================ serials
    /// Decode + SIGNATURE-VERIFY a serial.
    /// Throws `SecureCodeError` (malformed) / `SignatureError` (bad sig).
    public func parseSerial(_ serialText: String) throws -> LicensePayload {
        let (body, signature) = try Envelope.decode(serialText)
        let data = try WireJson.parseObject(String(decoding: body, as: UTF8.self))
        let payload = try LicensePayload.fromWire(data)
        guard Ed25519.verify(publicKey: publicKey(), message: body, signature: signature)
        else { throw SignatureError() }
        return payload
    }

    // ================================================================ blacklist
    private func loadBlacklist() -> Set<String> {
        guard let url = try? config.blacklistURL(),
              Self.fileSize(url) <= Self.maxBlacklistBytes,
              let text = try? String(contentsOf: url, encoding: .utf8)
        else { return [] }
        guard let (body, signature) = try? Envelope.decode(text),
              Ed25519.verify(publicKey: publicKey(), message: body, signature: signature)
        else { return [] }
        guard let data = try? WireJson.parseObject(String(decoding: body, as: UTF8.self))
        else { return [] }
        // Corrupt/forged blacklist is IGNORED (never brick the app on a
        // bad file) — but a correctly signed one always applies.
        guard (data["v"] as? Int) == 1 || (data["v"] as? NSNumber)?.intValue == 1
        else { return [] }
        let revoked = (data["revoked"] as? [Any]) ?? []
        return Set(revoked.map { "\($0)" })
    }

    // ================================================================ activation
    public func activate(_ serialText: String) -> ActivationResult {
        let serial = SCBase32.flatten(serialText) // normalized storage form
        if serial.isEmpty {
            return ActivationResult(ok: false, state: .missing,
                                     message: SecureStrings.s("msg_malformed"),
                                     payload: nil)
        }
        let payload: LicensePayload
        do {
            payload = try parseSerial(serial)
        } catch is SignatureError {
            return ActivationResult(ok: false, state: .invalid,
                                    message: SecureStrings.s("msg_invalid"),
                                    payload: nil)
        } catch {
            return ActivationResult(ok: false, state: .invalid,
                                    message: SecureStrings.s("msg_malformed"),
                                    payload: nil)
        }

        guard payload.productId == config.productId else {
            return ActivationResult(ok: false, state: .invalid,
                                     message: SecureStrings.s("msg_product"),
                                     payload: nil)
        }

        guard Fingerprint.matches(config, targetCode: payload.fingerprint,
                                  tolerance: payload.tolerance) else {
            return ActivationResult(ok: false, state: .wrongMachine,
                                    message: SecureStrings.s("msg_other_machine"),
                                    payload: nil)
        }

        let now = Int64(Date().timeIntervalSince1970)
        if payload.issuedAt - now > Int64(config.clockToleranceHours * 3600) {
            return ActivationResult(ok: false, state: .clockTampered,
                                    message: SecureStrings.s("msg_future"),
                                    payload: nil)
        }
        if !payload.isLifetime, now >= payload.expiresAt {
            return ActivationResult(ok: false, state: .expired,
                                    message: SecureStrings.s("msg_expired"),
                                    payload: nil)
        }

        if !payload.nonce.isEmpty, loadBlacklist().contains(payload.nonce) {
            return ActivationResult(ok: false, state: .revoked,
                                    message: SecureStrings.s("msg_revoked"),
                                    payload: nil)
        }

        var record = LicenseRecord(serial: serial, payload: payload.toWire(),
                                   activatedAt: now, lastSeen: now, rollbacks: 0,
                                   machineCode: machineCode())
        _ = try? writeLicenseFile(&record)
        clock.resetStores(machineCode(), lastSeen: now)
        return ActivationResult(ok: true, state: .valid, message: "", payload: payload)
    }

    // ================================================================ verification
    public func verifyInstalled() -> LicenseStatus {
        verifyInstalled(degraded: false)
    }

    public func verifyInstalled(degraded: Bool) -> LicenseStatus {
        if degraded {
            // Silent degrade requested by the anti-RE layer: generic damage
            // message, no hint about the real reason.
            return LicenseStatus(state: .degraded,
                                  message: SecureStrings.s("msg_damaged"),
                                  payload: nil, secondsLeft: -1)
        }

        var record: LicenseRecord
        do {
            record = try readLicenseFile()
        } catch is LicenseMissing {
            return LicenseStatus(state: .missing,
                                  message: SecureStrings.s("msg_not_installed"),
                                  payload: nil, secondsLeft: -1)
        } catch {
            return LicenseStatus(state: .damaged,
                                  message: SecureStrings.s("msg_damaged"),
                                  payload: nil, secondsLeft: -1)
        }

        // 1) Re-verify the STORED serial signature on every launch.
        let payload: LicensePayload
        do {
            payload = try parseSerial(record.serial)
        } catch is SignatureError {
            return LicenseStatus(state: .invalid,
                                 message: SecureStrings.s("msg_invalid"),
                                 payload: nil, secondsLeft: -1)
        } catch {
            return LicenseStatus(state: .damaged,
                                 message: SecureStrings.s("msg_damaged"),
                                 payload: nil, secondsLeft: -1)
        }

        // 2) Machine binding.
        if record.machineCode != machineCode() ||
            !Fingerprint.matches(config, targetCode: payload.fingerprint,
                                 tolerance: payload.tolerance) {
            return LicenseStatus(state: .wrongMachine,
                                 message: SecureStrings.s("msg_other_machine"),
                                 payload: nil, secondsLeft: -1)
        }

        // 3) Expiry.
        let now = Int64(Date().timeIntervalSince1970)
        if !payload.isLifetime, now >= payload.expiresAt {
            return LicenseStatus(state: .expired,
                                 message: SecureStrings.s("msg_expired"),
                                 payload: payload, secondsLeft: 0)
        }

        // 4) Anti-clock-rollback (allowance comes from the SIGNED payload).
        let decision = clock.evaluate(machineCode: machineCode(),
                                       licenseLastSeen: record.lastSeen,
                                       licenseRollbacks: record.rollbacks,
                                       allowance: payload.rollbackAllowance)
        record.lastSeen = decision.lastSeen
        record.rollbacks = decision.rollbacks
        if !decision.ok {
            return LicenseStatus(state: .clockTampered,
                                 message: SecureStrings.s("msg_clock"),
                                 payload: payload, secondsLeft: -1)
        }

        // 5) Revocation blacklist (re-read every launch).
        if !payload.nonce.isEmpty, loadBlacklist().contains(payload.nonce) {
            return LicenseStatus(state: .revoked,
                                 message: SecureStrings.s("msg_revoked"),
                                 payload: payload, secondsLeft: -1)
        }

        // 6) Persist the watermark back into the authenticated file.
        _ = try? writeLicenseFile(&record)

        return LicenseStatus(state: .valid, message: "", payload: payload,
                              secondsLeft: payload.secondsLeft(now: now))
    }

    // ================================================================ transfer
    /// Export the (signed) serial + machine code for a device transfer.
    public func makeDeactivationRequest(to url: URL) throws -> URL {
        let record = try readLicenseFile()
        let nonce = record.payload["n"] as? String ?? ""
        let payload: [String: Any] = [
            "format": SecureStrings.s("deact_request_format"),
            "version": 1,
            "product_id": config.productId,
            "machine_code": machineCode(),
            "serial": record.serial,
            "nonce": nonce,
            "created": Int(Date().timeIntervalSince1970),
        ]
        try WireJson.prettyPrint(payload).write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    /// Consume the vendor's signed transfer permit on the OLD device.
    public func deactivateWithPermit(at url: URL) -> (Bool, String) {
        guard Self.fileSize(url) <= Self.maxPermitBytes,
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return (false, "Permit file could not be read.")
        }
        guard let (body, signature) = try? Envelope.decode(text.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return (false, "Permit file is malformed.") }
        guard Ed25519.verify(publicKey: publicKey(), message: body, signature: signature)
        else { return (false, "Permit signature is invalid.") }
        guard let permit = try? WireJson.parseObject(String(decoding: body, as: UTF8.self))
        else { return (false, "Permit is malformed.") }
        let versionOK = (permit["v"] as? Int) == 1 || (permit["v"] as? NSNumber)?.intValue == 1
        guard versionOK, permit["action"] as? String == SecureStrings.s("deact_permit_action")
        else { return (false, "Permit is not a transfer permit.") }

        guard let record = try? readLicenseFile() else {
            return (false, "No license is installed on this device.")
        }
        let installedNonce = record.payload["n"] as? String ?? ""
        guard permit["old_nonce"] as? String == installedNonce else {
            return (false, "Permit does not match the installed serial.")
        }

        // Wipe license + clock evidence, keep a receipt file.
        try? FileManager.default.removeItem(at: config.licenseURL())
        clock.resetStores(machineCode(), lastSeen: 0)
        let receiptURL = config.dataDir()
            .appendingPathComponent(SecureStrings.s("receipt_name"))
        let receipt: [String: Any] = [
            "format": "securecode-deactivation-receipt",
            "version": 1,
            "nonce": permit["old_nonce"] ?? "",
            "deactivated_at": Int(Date().timeIntervalSince1970),
        ]
        try? WireJson.prettyPrint(receipt).write(to: receiptURL, atomically: true, encoding: .utf8)
        return (true, "License removed. You can now activate on the new device.")
    }

    // ================================================================ license file I/O
    private struct LicenseMissing: Error {}

    private struct LicenseRecord {
        var serial: String
        var payload: [String: Any]
        var activatedAt: Int64
        var lastSeen: Int64
        var rollbacks: Int64
        var machineCode: String
        var blacklistVer: Int64 = 0
    }

    private func readLicenseFile() throws -> LicenseRecord {
        let url = try config.licenseURL()
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw LicenseMissing()
        }
        // Size cap before reading (resource-exhaustion hardening; a real
        // license is ~2 KB). Too-large -> treated like any damaged store.
        guard Self.fileSize(url) <= Self.maxLicenseBytes else {
            throw SecureCodeError("license file too large")
        }
        let blob = [UInt8](try Data(contentsOf: url))
        guard blob.count > LicenseClient.licenseMagic.count,
              Array(blob.prefix(LicenseClient.licenseMagic.count)) == LicenseClient.licenseMagic
        else { throw SecureCodeError("bad magic") }
        let plain: [UInt8]
        do {
            plain = try CryptoUtils.gcmDecrypt(key: fileKey(),
                    blob: Array(blob.dropFirst(LicenseClient.licenseMagic.count)))
        } catch {
            throw SecureCodeError("license file unreadable")
        }
        guard let data = try? WireJson.parseObject(String(decoding: plain, as: UTF8.self))
        else { throw SecureCodeError("bad record") }
        let payload = data["payload"] as? [String: Any] ?? [:]
        let record = LicenseRecord(
            serial: data["serial"] as? String ?? "",
            payload: payload,
            activatedAt: (data["activated_at"] as? NSNumber)?.int64Value ?? 0,
            lastSeen: (data["last_seen"] as? NSNumber)?.int64Value ?? 0,
            rollbacks: (data["rollbacks"] as? NSNumber)?.int64Value ?? 0,
            machineCode: data["machine_code"] as? String ?? "")
        if record.serial.isEmpty { throw SecureCodeError("bad record") }
        return record
    }

    private func writeLicenseFile(_ record: inout LicenseRecord) throws {
        let plain: [String: Any] = [
            "v": 1,
            "serial": record.serial,
            "payload": record.payload,
            "activated_at": record.activatedAt,
            "last_seen": record.lastSeen,
            "rollbacks": record.rollbacks,
            "machine_code": record.machineCode,
            "blacklist_ver": record.blacklistVer,
        ]
        let bytes = try WireJson.canonicalBytes(plain)
        var blob = LicenseClient.licenseMagic
        blob.append(contentsOf: try CryptoUtils.gcmEncrypt(key: fileKey(), plaintext: bytes))
        let url = try config.licenseURL()
        try Data(blob).write(to: url, options: .atomic)
    }

    // ================================================================ utilities
    /// Customer string of the locally installed license (or "").
    public func installedCustomer() -> String {
        ((try? readLicenseFile())?.payload["cust"] as? String) ?? ""
    }

    /// Expiry unix timestamp of the installed license (or 0).
    public func installedExpiresAt() -> Int64 {
        ((try? readLicenseFile())?.payload["exp"] as? NSNumber)?.int64Value ?? 0
    }
}
