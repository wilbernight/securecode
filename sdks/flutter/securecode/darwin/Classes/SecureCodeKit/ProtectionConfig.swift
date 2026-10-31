import Foundation

/// What the anti-RE layer does when a debugger/trace is detected.
public enum DetectAction {
    /// Silent delayed process exit — looks like a normal crash/close.
    case exit
    /// Licensing checks start failing with a generic "damaged" error.
    case degrade
}

/// All knobs of the protection stack (Swift port of
/// target_demo/protection.ProtectionConfig — same defaults).
///
/// **devMode must NEVER be true in a release build.**
public struct ProtectionConfig {

    public let productId: String
    public let productName: String
    public let companyName: String

    /// Embedded Ed25519 public key (default: the shipped DEMO keypair —
    /// replace for real products with the protector's exported key).
    public let publicKey: [UInt8]

    public let antiDebugEnabled: Bool
    /// Emulator/jailbreak heuristics — OFF by default (same rationale as
    /// the Windows client: false positives cost more than the marginal
    /// protection gain).
    public let emulatorChecks: Bool
    public let timingChecks: Bool
    public let onDetect: DetectAction
    public let detectDelayRangeSeconds: (min: Int, max: Int)
    public let watchdogIntervalSeconds: (min: Int, max: Int)

    public let integrityChecks: Bool
    /// macOS only: require the app's code signature to validate at
    /// runtime. OFF by default because unsigned dev builds would break
    /// early development; ALWAYS enable for production.
    public let requireCodeSignature: Bool

    public let fingerprintTolerance: Int
    public let clockToleranceHours: Int
    public let defaultRollbackAllowance: Int

    public let devMode: Bool

    public init(
        productId: String,
        productName: String = "SecureApp",
        companyName: String = "SecureCode",
        publicKey: [UInt8]? = nil,
        antiDebugEnabled: Bool = true,
        emulatorChecks: Bool = false,
        timingChecks: Bool = true,
        onDetect: DetectAction = .exit,
        detectDelayRangeSeconds: (min: Int, max: Int) = (2, 8),
        watchdogIntervalSeconds: (min: Int, max: Int) = (20, 45),
        integrityChecks: Bool = true,
        requireCodeSignature: Bool = false,
        fingerprintTolerance: Int = 1,
        clockToleranceHours: Int = 24,
        defaultRollbackAllowance: Int = 3,
        devMode: Bool = false,
    ) {
        self.productId = productId
        self.productName = productName
        self.companyName = companyName
        self.publicKey = publicKey ?? CryptoUtils.fromHex(SecureStrings.s("pubkey"))
        self.antiDebugEnabled = antiDebugEnabled
        self.emulatorChecks = emulatorChecks
        self.timingChecks = timingChecks
        self.onDetect = onDetect
        self.detectDelayRangeSeconds = detectDelayRangeSeconds
        self.watchdogIntervalSeconds = watchdogIntervalSeconds
        self.integrityChecks = integrityChecks
        self.requireCodeSignature = requireCodeSignature
        self.fingerprintTolerance = fingerprintTolerance
        self.clockToleranceHours = clockToleranceHours
        self.defaultRollbackAllowance = defaultRollbackAllowance
        self.devMode = devMode
        precondition(self.publicKey.count == 32, "Ed25519 public key must be 32 bytes")
    }

    /// Convenience: decode the protector's hex public-key export into raw
    /// Ed25519 bytes for `publicKey:`.
    public static func publicKey(fromHex hex: String) -> [UInt8] {
        CryptoUtils.fromHex(hex.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    // ------------------------------------------------------------ locations
    /// Sandbox Application Support/<company>/<product>.
    public func dataDir() throws -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory,
                                            in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
        let dir = base
            .appendingPathComponent(companyName, isDirectory: true)
            .appendingPathComponent(productName, isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    public func licenseURL() throws -> URL {
        try dataDir().appendingPathComponent(SecureStrings.s("license_name"))
    }

    public func blacklistURL() throws -> URL {
        try dataDir().appendingPathComponent(SecureStrings.s("blacklist_name"))
    }

    /// DEMO product UUID (SecureNotepad) — matches the shipped demo keypair,
    /// so the SDK verifies demo serials out of the box.
    public static let demoProductId = "7e9a6cec-c185-45bb-a2fb-d31e96484f7e"
}
