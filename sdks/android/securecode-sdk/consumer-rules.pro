# Keep the client API surface (called from app code, sometimes reflectively
# from Flutter glue). Everything else is internal to the app already.
-keep class com.securecode.protection.LicenseClient { *; }
-keep class com.securecode.protection.LicensePayload { *; }
-keep class com.securecode.protection.ProtectionConfig$Builder { *; }
-keep class com.securecode.protection.ProtectionConfig { *; }
-keep class com.securecode.protection.ProtectionRuntime { *; }
-keep class com.securecode.protection.ProtectionRuntime$Handle { *; }
-keep class com.securecode.protection.SecureCodeSelfTest { *; }
-keep class com.securecode.protection.LicenseState { *; }
-keep class com.securecode.protection.DetectAction { *; }
-keep class com.securecode.protection.ActivationResult { *; }
-keep class com.securecode.protection.LicenseStatus { *; }
-keep class com.securecode.protection.SecureCodeException { *; }
-keep class com.securecode.protection.SignatureException { *; }
