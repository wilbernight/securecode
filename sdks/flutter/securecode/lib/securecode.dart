/// SecureCode — offline licensing client for Flutter (Android, iOS, macOS).
///
/// The Dart layer is a thin, fully-typed wrapper over the same native SDKs
/// used by Kotlin/Java/Swift apps (sdks/android, sdks/apple); the serial
/// keys, machine codes, blacklists and transfer permits are IDENTICAL
/// across every platform.
///
/// Typical integration (see the example/ app for a complete flow):
///
/// ```dart
/// final secureCode = SecureCode.instance;
/// await secureCode.initialize(ProtectionConfig(
///   productId: '7e9a6cec-c185-45bb-a2fb-d31e96484f7e',
///   productName: 'MyApp',
/// ));
/// final status = await secureCode.verifyInstalled();
/// if (!status.isValid) {
///   final result = await secureCode.activate(serialFromUser);
///   ...
/// }
/// ```
library securecode;

export 'src/types.dart';
export 'src/client.dart';
