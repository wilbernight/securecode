package com.securecode.protection

import android.content.Context
import android.content.pm.PackageManager

/**
 * Self-integrity layer (Android analog of the Windows integrity manifest —
 * in a signed APK the manifest hash has no equivalent attacker-relevant
 * value, so the meaningful checks are):
 *
 *     1. APK signer certificate digest — optionally pinned to YOUR release
 *        certificate (config.expectedSignerCertSha256): a repackaged or
 *        resigned APK fails hard.
 *     2. debuggable flag — release builds must never be debuggable.
 *     3. embedded public key sanity (32 bytes — matches the builder's
 *        requirement, double-checked at runtime).
 *
 * Hard failure -> the runtime exits silently (graceful, non-obvious
 * termination — same policy as the Windows client).
 */
internal object Integrity {

    fun runChecks(context: Context, config: ProtectionConfig): Pair<Boolean, List<String>> {
        val problems = ArrayList<String>()
        try {
            if (config.expectedSignerCertSha256.isNotEmpty()) {
                val digest = signerCertSha256(context)
                if (digest != config.expectedSignerCertSha256) {
                    problems.add("signer-mismatch")
                }
            }
            val flags = context.applicationInfo.flags
            if ((flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                problems.add("debuggable")
            }
            if (config.publicKey.size != 32) problems.add("pubkey-size")
        } catch (t: Throwable) {
            problems.add("unavailable")
        }
        return Pair(problems.isEmpty(), problems)
    }

    /** SHA-256 hex of the APK signing certificate (API-28-aware). */
    fun signerCertSha256(context: Context): String {
        val pm = context.packageManager
        val packageName = context.packageName
        val encoded: ByteArray =
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES)
                val cert = info.signingInfo?.apkContentsSigners?.firstOrNull()
                    ?: throw SecureCodeException("no signing certificate")
                cert.encoded
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                val sig = info.signatures?.firstOrNull()
                    ?: throw SecureCodeException("no signatures")
                sig.toByteArray()
            }
        return CryptoUtils.toHex(CryptoUtils.sha256(encoded))
    }
}
