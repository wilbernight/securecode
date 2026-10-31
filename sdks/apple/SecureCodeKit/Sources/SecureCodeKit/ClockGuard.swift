import Foundation
import Darwin

/// Anti-clock-rollback (offline expiry enforcement) — the iOS/macOS port
/// of target_demo/protection/clock_guard.py.
///
/// A monotonically increasing "last seen" watermark is kept in THREE
/// independent local stores:
///
///     1. the AES-GCM-authenticated license file (managed by LicenseClient)
///     2. the Keychain (machine-bound key; survives app reinstalls)
///     3. UserDefaults decoy value (obfuscated — the analog of the Windows
///        registry/decoy-file pair)
///
/// On every evaluation the guard reads all stores, takes the MAXIMUM
/// timestamp and compares with the wall clock; a setback beyond
/// clockToleranceHours counts as a rollback event (allowance comes from
/// the SIGNED payload). Editing a store breaks decryption, which the
/// guard treats as a reset (the GCM license file stays authoritative).
///
/// Mid-session detection: ProcessInfo.systemUptime (monotonic since boot)
/// cross-checked against the wall clock.
final class ClockGuard {

    struct ClockDecision {
        let ok: Bool
        let lastSeen: Int64
        let rollbacks: Int64
        let rolledBackNow: Bool
    }

    private let config: ProtectionConfig
    private let clockContext = "clock-store-v1"
    private var sessionWall: Double?
    private var sessionTick: Double?

    /// Keychain watermark store (nil when Keychain is unavailable).
    private var keychainAccount: String {
        "clock-" + config.productId
    }

    init(_ config: ProtectionConfig) {
        self.config = config
    }

    private func master() -> [UInt8] { SecureStrings.bytes("license_master") }

    // ------------------------------------------------------------ stores
    private func seal(_ machineCode: String, _ lastSeen: Int64, _ rollbacks: Int64) -> [UInt8] {
        // AES-GCM under the machine-bound key (platform-internal format —
        // the Windows client uses AES-CTR for the same stores; stores never
        // cross platforms, so the authenticated form is used here).
        var plain = CryptoUtils.packU64(UInt64(lastSeen))
        plain.append(contentsOf: CryptoUtils.packU64(UInt64(rollbacks)))
        let key = CryptoUtils.deriveMachineKey(master: master(), machineCode: machineCode,
                                                productId: config.productId,
                                                context: clockContext)
        return (try? CryptoUtils.gcmEncrypt(key: key, plaintext: plain)) ?? []
    }

    private func unseal(_ machineCode: String, _ blob: [UInt8]) -> (Int64, Int64)? {
        guard blob.count > 12 + 16 else { return nil }
        let key = CryptoUtils.deriveMachineKey(master: master(), machineCode: machineCode,
                                                productId: config.productId,
                                                context: clockContext)
        guard let plain = try? CryptoUtils.gcmDecrypt(key: key, blob: blob),
              plain.count >= 16 else { return nil }
        let lastSeen = Int64(bitPattern: CryptoUtils.unpackU64(Array(plain.prefix(8))))
        let rollbacks = Int64(bitPattern: CryptoUtils.unpackU64(Array(plain.dropFirst(8).prefix(8))))
        return (lastSeen, rollbacks)
    }

    private func readKeychain(_ machineCode: String) -> (Int64, Int64)? {
        guard let text = KeychainStore.read(service: "com.securecode.clock",
                                            account: keychainAccount),
              let blob = Data(base64Encoded: text, options: .ignoreUnknownCharacters)
        else { return nil }
        return unseal(machineCode, Array(blob))
    }

    private func writeKeychain(_ machineCode: String, _ lastSeen: Int64, _ rollbacks: Int64) {
        let blob = seal(machineCode, lastSeen, rollbacks)
        guard !blob.isEmpty else { return }
        _ = KeychainStore.write(service: "com.securecode.clock",
                                account: keychainAccount,
                                bytes: Array(blob))
    }

    private func readDefaults(_ machineCode: String) -> (Int64, Int64)? {
        let key = "sc_sync_" + config.productId
        guard let text = UserDefaults.standard.string(forKey: key),
              let blob = Data(base64Encoded: text, options: .ignoreUnknownCharacters)
        else { return nil }
        return unseal(machineCode, Array(blob))
    }

    private func writeDefaults(_ machineCode: String, _ lastSeen: Int64, _ rollbacks: Int64) {
        let blob = seal(machineCode, lastSeen, rollbacks)
        guard !blob.isEmpty else { return }
        UserDefaults.standard.set(blob.base64EncodedString(), forKey: "sc_sync_" + config.productId)
    }

    // ------------------------------------------------------------ API
    func now() -> Int64 { Int64(Date().timeIntervalSince1970) }

    /// Clear/re-seed all stores (fresh activation or deactivation).
    func resetStores(_ machineCode: String, lastSeen: Int64) {
        writeKeychain(machineCode, lastSeen, 0)
        writeDefaults(machineCode, lastSeen, 0)
    }

    /// Mid-session clock-change detection; true == clean.
    func sessionCheck() -> Bool {
        let wall = Date().timeIntervalSince1970
        let tick = ProcessInfo.processInfo.systemUptime
        if let sw = sessionWall, let st = sessionTick {
            defer { sessionWall = wall; sessionTick = tick }
            let wallDelta = wall - sw
            let tickDelta = tick - st
            // Wall clock rewound while the monotonic clock advanced.
            return !(wallDelta < -1.0 && tickDelta > 1.0)
        }
        sessionWall = wall
        sessionTick = tick
        return true
    }

    /// Full anti-rollback evaluation (see class docstring).
    func evaluate(machineCode: String, licenseLastSeen: Int64,
                  licenseRollbacks: Int64, allowance: Int) -> ClockDecision {
        let toleranceSeconds = Int64(config.clockToleranceHours * 3600)
        var stored: [(Int64, Int64)] = []
        if let k = readKeychain(machineCode) { stored.append(k) }
        if let d = readDefaults(machineCode) { stored.append(d) }
        stored.append((licenseLastSeen, licenseRollbacks))

        var lastSeen = stored.map { $0.0 }.max() ?? 0
        var rollbacks = stored.map { $0.1 }.max() ?? 0
        let now = self.now()

        var rolledBack = false
        var ok: Bool
        if now < lastSeen - toleranceSeconds {
            rollbacks += 1
            rolledBack = true
            ok = rollbacks <= Int64(allowance)
        } else {
            ok = true
            lastSeen = max(now, lastSeen)
        }
        writeKeychain(machineCode, lastSeen, rollbacks)    // persist even on
        writeDefaults(machineCode, lastSeen, rollbacks)   // failure — evidence survives
        return ClockDecision(ok: ok, lastSeen: lastSeen, rollbacks: rollbacks,
                             rolledBackNow: rolledBack)
    }
}
