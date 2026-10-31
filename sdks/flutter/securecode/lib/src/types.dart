/// Shared value types for the SecureCode Flutter plugin (mirror of the
/// native SDK enums/results 1:1).
library;

/// Every terminal state of the local license evaluation (native
/// LicenseState).
enum LicenseState {
  valid,
  missing,
  invalid,
  expired,
  wrongMachine,
  revoked,
  clockTampered,
  damaged,
  degraded;

  static LicenseState fromName(String name) =>
      LicenseState.values.firstWhere(
        (s) => s.name == name,
        orElse: () => LicenseState.invalid,
      );
}

/// What the anti-RE layer does on debugger detection (native DetectAction).
enum DetectAction { exit, degrade }

/// All knobs of the protection stack (native ProtectionConfig).
class ProtectionConfig {
  const ProtectionConfig({
    required this.productId,
    this.productName = 'SecureApp',
    this.companyName = 'SecureCode',
    this.publicKeyHex,
    this.antiDebugEnabled = true,
    this.emulatorChecks = false,
    this.timingChecks = true,
    this.onDetect = DetectAction.exit,
    this.detectDelayRangeSeconds = const (2, 8),
    this.watchdogIntervalSeconds = const (20, 45),
    this.integrityChecks = true,
    this.expectedSignerCertSha256,
    this.fingerprintTolerance = 1,
    this.clockToleranceHours = 24,
    this.defaultRollbackAllowance = 3,
    this.devMode = false,
    this.useKeystoreComponent = false,
    this.requireCodeSignature = false,
  });

  /// Product UUID — must match the serial's "pid" field.
  final String productId;

  /// Used for directory naming on the native side.
  final String productName;
  final String companyName;

  /// Ed25519 public key as hex (the protector's export). Default: the
  /// shipped DEMO keypair — replace for real products.
  final String? publicKeyHex;

  /// Anti-debug + integrity switches. devMode must NEVER be true in a
  /// release build (it disables the anti-RE layer for debugging).
  final bool antiDebugEnabled;
  final bool emulatorChecks;
  final bool timingChecks;
  final DetectAction onDetect;
  final (int, int) detectDelayRangeSeconds;
  final (int, int) watchdogIntervalSeconds;
  final bool integrityChecks;

  /// Android: optional hard pin of your APK signing certificate digest.
  final String? expectedSignerCertSha256;

  /// macOS: require a valid code signature at runtime (enable for
  /// production).
  final bool requireCodeSignature;

  final int fingerprintTolerance;
  final int clockToleranceHours;
  final int defaultRollbackAllowance;
  final bool devMode;

  /// Android: extra per-install Keystore binding (default off — keeps the
  /// machine code stable across uninstall/reinstall).
  final bool useKeystoreComponent;

  Map<String, Object?> toWire() => {
        'productId': productId,
        'productName': productName,
        'companyName': companyName,
        'publicKeyHex': publicKeyHex,
        'antiDebugEnabled': antiDebugEnabled,
        'emulatorChecks': emulatorChecks,
        'timingChecks': timingChecks,
        'onDetect': onDetect.name,
        'detectDelayMin': detectDelayRangeSeconds.$1,
        'detectDelayMax': detectDelayRangeSeconds.$2,
        'watchdogMin': watchdogIntervalSeconds.$1,
        'watchdogMax': watchdogIntervalSeconds.$2,
        'integrityChecks': integrityChecks,
        'expectedSignerCertSha256': expectedSignerCertSha256,
        'fingerprintTolerance': fingerprintTolerance,
        'clockToleranceHours': clockToleranceHours,
        'defaultRollbackAllowance': defaultRollbackAllowance,
        'devMode': devMode,
        'useKeystoreComponent': useKeystoreComponent,
        'requireCodeSignature': requireCodeSignature,
      };
}

/// Result of activate().
class ActivationResult {
  const ActivationResult({
    required this.ok,
    required this.state,
    required this.message,
    this.payload,
  });

  final bool ok;
  final LicenseState state;
  final String message;
  final LicensePayload? payload;
}

/// Result of verifyInstalled().
class LicenseStatus {
  const LicenseStatus({
    required this.state,
    required this.message,
    required this.secondsLeft,
    this.payload,
  });

  final LicenseState state;
  final String message;
  final int secondsLeft;
  final LicensePayload? payload;

  bool get isValid => state == LicenseState.valid;
}

/// The signed body of a serial key (parsed, verified — never secret).
class LicensePayload {
  const LicensePayload({
    required this.fingerprint,
    required this.productId,
    required this.issuedAt,
    required this.expiresAt,
    required this.customer,
    required this.nonce,
    required this.featureFlags,
    required this.tolerance,
    required this.rollbackAllowance,
    required this.version,
  });

  final String fingerprint;
  final String productId;
  final int issuedAt;
  final int expiresAt; // 0 = lifetime
  final String customer;
  final String nonce;
  final Map<String, bool> featureFlags;
  final int tolerance;
  final int rollbackAllowance;
  final int version;

  bool get isLifetime => expiresAt == 0;

  static LicensePayload? fromWire(Object? wire) {
    if (wire is! Map) return null;
    return LicensePayload(
      fingerprint: wire['fp'] as String? ?? '',
      productId: wire['pid'] as String? ?? '',
      issuedAt: (wire['iat'] as num?)?.toInt() ?? 0,
      expiresAt: (wire['exp'] as num?)?.toInt() ?? 0,
      customer: wire['cust'] as String? ?? '',
      nonce: wire['n'] as String? ?? '',
      featureFlags: (wire['fl'] as Map?)?.map(
          (k, v) => MapEntry(k as String, v == true)),
      tolerance: (wire['tol'] as num?)?.toInt() ?? 1,
      rollbackAllowance: (wire['rb'] as num?)?.toInt() ?? 3,
      version: (wire['v'] as num?)?.toInt() ?? 1,
    );
  }
}

/// Result of deactivateWithPermit().
class DeactivationResult {
  const DeactivationResult({required this.ok, required this.message});

  final bool ok;
  final String message;
}

/// Cross-platform conformance self-test report (native
/// SecureCodeSelfTest). allOk == true proves byte-exact wire
/// compatibility on the CURRENT device — a good release smoke test.
class SelfTestReport {
  const SelfTestReport({
    required this.allOk,
    required this.entries,
  });

  final bool allOk;
  final List<SelfTestEntry> entries;
}

class SelfTestEntry {
  const SelfTestEntry({
    required this.name,
    required this.ok,
    required this.detail,
  });

  final String name;
  final bool ok;
  final String detail;

  /// The report as the JSON consumed by
  /// `python -m tests.cross_platform_vectors --check`.
  Map<String, Object?> toWire() => {'name': name, 'ok': ok, 'detail': detail};
}
