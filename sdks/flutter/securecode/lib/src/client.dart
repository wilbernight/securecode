import 'dart:async';

import 'package:flutter/services.dart';

import 'types.dart';

/// The SecureCode client — a thin, typed wrapper over the platform channel
/// to the native SDKs (Kotlin on Android, Swift on iOS/macOS).
///
/// All methods run the native verification synchronously on a background
/// platform thread — safe to call from the UI isolate, but machineCode()
/// and activate() may take a moment on first use (fingerprint collection).
class SecureCode {
  SecureCode._();

  static const MethodChannel _channel = MethodChannel('securecode/licensing');

  static final SecureCode instance = SecureCode._();

  ProtectionConfig? _config;

  /// Wire the native side with [config]. Call once at startup (before any
  /// other method); also starts the anti-RE runtime (integrity +
  /// anti-debug watchdog) unless devMode is set.
  Future<void> initialize(ProtectionConfig config) async {
    await _channel.invokeMethod<void>('init', config.toWire());
    _config = config;
  }

  /// This device's machine code "XXXX-XXXX-XXXX-XXXX" — what the customer
  /// sends you (the vendor) to get a serial issued.
  Future<String> machineCode() async {
    return (await _channel.invokeMethod<String>('machineCode'))!;
  }

  /// Full activation flow (see the native LicenseClient.activate docstring):
  /// verify signature -> product -> machine lock -> clock sanity ->
  /// expiry -> blacklist -> write the encrypted local license.
  Future<ActivationResult> activate(String serial) async {
    final wire = await _channel
        .invokeMapMethod<String, Object?>('activate', {'serial': serial});
    return ActivationResult(
      ok: wire!['ok'] as bool? ?? false,
      state: LicenseState.fromName(wire['state'] as String? ?? 'invalid'),
      message: wire['message'] as String? ?? '',
      payload: LicensePayload.fromWire(wire['payload']),
    );
  }

  /// Launch-time verification of the local license (100% offline): stored
  /// signature re-verified, machine binding, expiry, clock guard,
  /// blacklist.
  Future<LicenseStatus> verifyInstalled() async {
    final wire = await _channel.invokeMapMethod<String, Object?>('verify');
    return LicenseStatus(
      state: LicenseState.fromName(wire!['state'] as String? ?? 'invalid'),
      message: wire['message'] as String? ?? '',
      secondsLeft: (wire['secondsLeft'] as num?)?.toInt() ?? -1,
      payload: LicensePayload.fromWire(wire['payload']),
    );
  }

  /// True when the anti-RE layer switched to silent-degrade mode (feed
  /// this into your error handling: show the generic "damaged" message).
  Future<bool> degraded() async {
    return await _channel.invokeMethod<bool>('degraded') ?? false;
  }

  /// Write the fingerprint export file (machine code + present components
  /// + platform tag — NO raw hardware identifiers) for the customer to
  /// send to the vendor. Returns the absolute path written.
  Future<String> exportFingerprintFile(String path) async {
    return (await _channel.invokeMethod<String>(
        'exportFingerprint', {'path': path}))!;
  }

  /// Export the deactivation request (signed serial + machine code) for a
  /// device transfer. Returns the absolute path written.
  Future<String> makeDeactivationRequest(String path) async {
    return (await _channel.invokeMethod<String>(
        'makeDeactivationRequest', {'path': path}))!;
  }

  /// Consume the vendor's signed transfer permit on the OLD device
  /// (wipes the local license + clock stores, writes a receipt).
  Future<DeactivationResult> deactivateWithPermit(String path) async {
    final wire = await _channel
        .invokeMapMethod<String, Object?>('deactivateWithPermit', {'path': path});
    return DeactivationResult(
      ok: wire!['ok'] as bool? ?? false,
      message: wire['message'] as String? ?? '',
    );
  }

  /// Customer string of the locally installed license (or "").
  Future<String> installedCustomer() async {
    return await _channel.invokeMethod<String>('installedCustomer') ?? '';
  }

  /// Expiry unix timestamp of the installed license (or 0).
  Future<int> installedExpiresAt() async {
    return await _channel.invokeMethod<int>('installedExpiresAt') ?? 0;
  }

  /// Run the cross-platform conformance vectors ON THIS DEVICE — pass the
  /// text of sdks/vectors.json (bundle it as an asset in dev builds). A
  /// cheap release smoke test on the platforms you ship to.
  Future<SelfTestReport> runSelfTest(String vectorsJson) async {
    final wire = await _channel
        .invokeMapMethod<String, Object?>('selfTest', {'vectors': vectorsJson});
    final entries = (wire!['results'] as List? ?? [])
        .map((e) => SelfTestEntry(
              name: (e as Map)['name'] as String? ?? '',
              ok: e['ok'] as bool? ?? false,
              detail: e['detail'] as String? ?? '',
            ))
        .toList();
    return SelfTestReport(
      allOk: wire['allOk'] as bool? ?? false,
      entries: entries,
    );
  }

  /// Stop the native anti-RE watchdog on clean application exit.
  Future<void> shutdown() async {
    await _channel.invokeMethod<void>('shutdown');
  }
}
