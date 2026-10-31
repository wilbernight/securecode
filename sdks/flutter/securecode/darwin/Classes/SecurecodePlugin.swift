#if canImport(Flutter)
import Flutter
#endif
import Foundation

/// MethodChannel glue ("securecode/licensing") between the Dart API and
/// SecureCodeKit (the same Swift SDK iOS/macOS apps use — synced in from
/// sdks/apple/SecureCodeKit by sdks/sync_native.py).
///
/// Shared-darwin-source plugin: this single implementation serves BOTH
/// iOS and macOS (Flutter >= 3.27, sharedDarwinSource: true).
public class SecurecodePlugin: NSObject, FlutterPlugin {

    private var config: ProtectionConfig?
    private var runtime: ProtectionRuntime.Handle?
    private var client: LicenseClient?
    private let queue = DispatchQueue(label: "com.securecode.plugin", qos: .userInitiated)

    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "securecode/licensing",
                                           binaryMessenger: registrar.messenger())
        let instance = SecurecodePlugin()
        channel.setMethodCallHandler { call, result in
            instance.handle(call, result: result)
        }
    }

    private func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "init":
            onQueue(result) {
                let args = call.arguments as? [String: Any] ?? [:]
                try initClient(args)
                return nil
            }
        case "machineCode":
            onQueue(result) { try client().machineCode() }
        case "activate":
            onQueue(result) {
                let serial = (call.arguments as? [String: Any])?["serial"] as? String ?? ""
                let r = try client().activate(serial)
                return [
                    "ok": r.ok,
                    "state": r.state.rawValue,
                    "message": r.message,
                    "payload": r.payload?.toWire() ?? NSNull(),
                ]
            }
        case "verify":
            onQueue(result) {
                let degraded = runtime?.degraded ?? false
                let s = try client().verifyInstalled(degraded: degraded)
                return [
                    "state": s.state.rawValue,
                    "message": s.message,
                    "secondsLeft": s.secondsLeft,
                    "payload": s.payload?.toWire() ?? NSNull(),
                ]
            }
        case "degraded":
            result(runtime?.degraded ?? false)
        case "exportFingerprint":
            onQueue(result) {
                let path = (call.arguments as? [String: Any])?["path"] as? String ?? ""
                let url = URL(fileURLWithPath: path)
                _ = try Fingerprint.exportFingerprintFile(try configRequired(), to: url)
                return url.path
            }
        case "makeDeactivationRequest":
            onQueue(result) {
                let path = (call.arguments as? [String: Any])?["path"] as? String ?? ""
                return try client().makeDeactivationRequest(
                    to: URL(fileURLWithPath: path)).path
            }
        case "deactivateWithPermit":
            onQueue(result) {
                let path = (call.arguments as? [String: Any])?["path"] as? String ?? ""
                let (ok, message) = try client().deactivateWithPermit(
                    at: URL(fileURLWithPath: path))
                return ["ok": ok, "message": message]
            }
        case "installedCustomer":
            onQueue(result) { client().installedCustomer() }
        case "installedExpiresAt":
            onQueue(result) { client().installedExpiresAt() }
        case "selfTest":
            onQueue(result) {
                let vectors = (call.arguments as? [String: Any])?["vectors"] as? String ?? ""
                let report = SecureCodeSelfTest.run(vectors)
                return [
                    "allOk": report.allOk,
                    "results": report.results.map { [
                        "name": $0.name, "ok": $0.ok, "detail": $0.detail,
                    ] as [String: Any] },
                ]
            }
        case "shutdown":
            onQueue(result) {
                runtime?.shutdown()
                return nil
            }
        default:
            result(FlutterMethodNotImplemented)
        }
    }

    // ---------------------------------------------------------------- helpers
    private func onQueue(_ result: @escaping FlutterResult, _ work: @escaping () throws -> Any?) {
        queue.async {
            do {
                if let value = try work() {
                    DispatchQueue.main.async { result(value) }
                } else {
                    DispatchQueue.main.async { result(nil) }
                }
            } catch {
                DispatchQueue.main.async {
                    result(FlutterError(code: "securecode",
                                        message: "\(error)",
                                        details: nil))
                }
            }
        }
    }

    private func client() throws -> LicenseClient {
        guard let c = client else {
            throw SecureCodeError("SecureCode not initialized — call initialize() first")
        }
        return c
    }

    private func configRequired() throws -> ProtectionConfig {
        guard let c = config else {
            throw SecureCodeError("SecureCode not initialized — call initialize() first")
        }
        return c
    }

    private func initClient(_ map: [String: Any]) throws {
        guard let productId = map["productId"] as? String else {
            throw SecureCodeError("productId is required")
        }
        let config = ProtectionConfig(
            productId: productId,
            productName: (map["productName"] as? String) ?? "SecureApp",
            companyName: (map["companyName"] as? String) ?? "SecureCode",
            publicKey: (map["publicKeyHex"] as? String).map(ProtectionConfig.publicKey(fromHex:)),
            antiDebugEnabled: (map["antiDebugEnabled"] as? Bool) ?? true,
            emulatorChecks: (map["emulatorChecks"] as? Bool) ?? false,
            timingChecks: (map["timingChecks"] as? Bool) ?? true,
            onDetect: (map["onDetect"] as? String) == "degrade" ? .degrade : .exit,
            detectDelayRangeSeconds: (
                (map["detectDelayMin"] as? Int) ?? 2,
                (map["detectDelayMax"] as? Int) ?? 8),
            watchdogIntervalSeconds: (
                (map["watchdogMin"] as? Int) ?? 20,
                (map["watchdogMax"] as? Int) ?? 45),
            integrityChecks: (map["integrityChecks"] as? Bool) ?? true,
            requireCodeSignature: (map["requireCodeSignature"] as? Bool) ?? false,
            fingerprintTolerance: (map["fingerprintTolerance"] as? Int) ?? 1,
            clockToleranceHours: (map["clockToleranceHours"] as? Int) ?? 24,
            defaultRollbackAllowance: (map["defaultRollbackAllowance"] as? Int) ?? 3,
            devMode: (map["devMode"] as? Bool) ?? false)
        self.config = config
        let runtimeHandle = ProtectionRuntime.bootstrap(config)
        self.runtime = runtimeHandle
        self.client = runtimeHandle.licenseClient(config)
    }
}
