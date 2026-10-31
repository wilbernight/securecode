package com.securecode.protection

import android.content.Context
import java.io.File

/** What the anti-RE layer does when a debugger/trace is detected. */
enum class DetectAction {
    /** Silent delayed process kill — looks like a normal crash/close. */
    EXIT,
    /** Licensing checks start failing with a generic "damaged" error. */
    DEGRADE,
}

/**
 * All knobs of the protection stack, per protected application (Android
 * port of target_demo/protection.ProtectionConfig — same defaults).
 *
 * Build one with [Builder] (Java-friendly):
 *
 * ```kotlin
 * val config = ProtectionConfig.Builder(productId = "…uuid…")
 *     .productName("MyApp")
 *     .devMode(BuildConfig.DEBUG)
 *     .build()
 * ```
 *
 * **devMode must NEVER be true in a release build.** It disables
 * anti-debug and integrity checks so developers can work under a debugger.
 */
class ProtectionConfig private constructor(builder: Builder) {

    val productId: String = builder.productId
    val productName: String = builder.productName
    val companyName: String = builder.companyName

    /** Embedded Ed25519 public key (default: the shipped DEMO keypair —
     *  replace for real products with the value exported from the
     *  protector's keystore). */
    val publicKey: ByteArray = builder.publicKey

    val antiDebugEnabled: Boolean = builder.antiDebugEnabled
    /** Emulator/rooted-environment heuristics — OFF by default (same
     *  rationale as the Windows client: false positives cost more support
     *  grief than the marginal protection). */
    val emulatorChecks: Boolean = builder.emulatorChecks
    val timingChecks: Boolean = builder.timingChecks
    val onDetect: DetectAction = builder.onDetect
    val detectDelayRangeSeconds: Pair<Int, Int> = builder.detectDelayRangeSeconds
    val watchdogIntervalSeconds: Pair<Int, Int> = builder.watchdogIntervalSeconds

    val integrityChecks: Boolean = builder.integrityChecks
    /** Optional hard pin: SHA-256 hex of YOUR APK signing certificate. When
     *  set, a repackaged/resigned APK fails integrity. */
    val expectedSignerCertSha256: String = builder.expectedSignerCertSha256

    val fingerprintTolerance: Int = builder.fingerprintTolerance
    val clockToleranceHours: Int = builder.clockToleranceHours
    val defaultRollbackAllowance: Int = builder.defaultRollbackAllowance

    val devMode: Boolean = builder.devMode
    /** Extra per-install binding via an Android Keystore keypair. OFF by
     *  default (keeps machine codes stable across uninstall/reinstall, so
     *  the same serial re-activates — Windows-like UX). */
    val useKeystoreComponent: Boolean = builder.useKeystoreComponent

    fun devModeActive(): Boolean = devMode

    // ------------------------------------------------------------ locations
    /** App-private state directory: files/<company>/<product>. */
    fun dataDir(context: Context): File =
        File(File(context.filesDir, companyName), productName)

    /** Encrypted local license file. */
    fun licenseFile(context: Context): File =
        File(dataDir(context), SecureStrings.s("license_name"))

    /** Optional signed revocation blacklist (distributed by the vendor). */
    fun blacklistFile(context: Context): File =
        File(dataDir(context), SecureStrings.s("blacklist_name"))

    /** Per-product Builder. */
    class Builder(val productId: String) {
        var productName: String = "SecureApp"
        var companyName: String = "SecureCode"
        var publicKey: ByteArray = CryptoUtils.fromHex(SecureStrings.s("pubkey"))
        var antiDebugEnabled: Boolean = true
        var emulatorChecks: Boolean = false
        var timingChecks: Boolean = true
        var onDetect: DetectAction = DetectAction.EXIT
        var detectDelayRangeSeconds: Pair<Int, Int> = Pair(2, 8)
        var watchdogIntervalSeconds: Pair<Int, Int> = Pair(20, 45)
        var integrityChecks: Boolean = true
        var expectedSignerCertSha256: String = ""
        var fingerprintTolerance: Int = 1
        var clockToleranceHours: Int = 24
        var defaultRollbackAllowance: Int = 3
        var devMode: Boolean = false
        var useKeystoreComponent: Boolean = false

        fun productName(v: String) = apply { productName = v }
        fun companyName(v: String) = apply { companyName = v }
        fun publicKey(v: ByteArray) = apply { publicKey = v }
        /** Ed25519 public key from hex (matches the protector's
         *  "public key" export). */
        fun publicKeyHex(v: String) = apply { publicKey = CryptoUtils.fromHex(v.trim()) }
        fun antiDebugEnabled(v: Boolean) = apply { antiDebugEnabled = v }
        fun emulatorChecks(v: Boolean) = apply { emulatorChecks = v }
        fun timingChecks(v: Boolean) = apply { timingChecks = v }
        fun onDetect(v: DetectAction) = apply { onDetect = v }
        fun detectDelayRangeSeconds(min: Int, max: Int) =
            apply { detectDelayRangeSeconds = Pair(min, max) }
        fun watchdogIntervalSeconds(min: Int, max: Int) =
            apply { watchdogIntervalSeconds = Pair(min, max) }
        fun integrityChecks(v: Boolean) = apply { integrityChecks = v }
        fun expectedSignerCertSha256(v: String) = apply { expectedSignerCertSha256 = v.trim().lowercase() }
        fun fingerprintTolerance(v: Int) = apply { fingerprintTolerance = v }
        fun clockToleranceHours(v: Int) = apply { clockToleranceHours = v }
        fun defaultRollbackAllowance(v: Int) = apply { defaultRollbackAllowance = v }
        fun devMode(v: Boolean) = apply { devMode = v }
        fun useKeystoreComponent(v: Boolean) = apply { useKeystoreComponent = v }

        fun build(): ProtectionConfig {
            require(productId.length >= 32) { "productId must be the product UUID" }
            require(publicKey.size == 32) { "Ed25519 public key must be 32 bytes" }
            return ProtectionConfig(this)
        }
    }

    companion object {
        /** DEMO product UUID (SecureNotepad) — matches the shipped demo
         *  keypair + serials, so the SDK verifies out of the box. */
        const val DEMO_PRODUCT_ID: String = "7e9a6cec-c185-45bb-a2fb-d31e96484f7e"
    }
}
