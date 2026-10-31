package com.securecode.protection

import android.content.Context
import android.os.SystemClock
import android.util.Base64
import java.io.File

/**
 * Anti-clock-rollback (offline expiry enforcement) — the Android port of
 * target_demo/protection/clock_guard.py.
 *
 * A monotonically increasing "last seen" watermark is kept in THREE
 * independent local stores:
 *
 *     1. the AES-GCM-authenticated license file (managed by LicenseClient)
 *     2. app-private SharedPreferences — obfuscated value (registry analog)
 *     3. a decoy file in cacheDir (analog of the Windows decoy file)
 *
 * On every evaluation the guard reads all stores, takes the MAXIMUM
 * timestamp and compares with the wall clock; a setback beyond
 * clockToleranceHours counts as a rollback event (allowance comes from the
 * SIGNED payload). Store payloads are AES-CTR-obfuscated with a
 * machine-bound key — editing breaks decryption, which the guard treats as
 * a reset (the GCM license file remains the authoritative watermark).
 *
 * Mid-session detection: SystemClock.elapsedRealtime() (monotonic since
 * boot) is cross-checked against the wall clock — if the wall moves
 * backwards while uptime moves forward, that is a tamper event.
 */
internal class ClockGuard(private val context: Context,
                          private val config: ProtectionConfig) {

    private val clockContext = "clock-store-v1"
    private var sessionWall: Double? = null
    private var sessionTick: Double? = null

    data class ClockDecision(
        val ok: Boolean,
        val lastSeen: Long,
        val rollbacks: Long,
        val rolledBackNow: Boolean,
    )

    private fun master(): ByteArray = SecureStrings.bytes("license_master")

    // ------------------------------------------------------------ stores
    private fun obfuscate(machineCode: String, data: ByteArray): ByteArray =
        CryptoUtils.ctrCrypt(machineCode, config.productId, clockContext, master(), data)

    private fun deobfuscate(machineCode: String, blob: ByteArray): ByteArray =
        CryptoUtils.ctrCrypt(machineCode, config.productId, clockContext, master(), blob)

    private fun prefs() = context.getSharedPreferences(
        SecureStrings.s("prefs_name"), Context.MODE_PRIVATE)

    private fun readPrefs(machineCode: String): Pair<Long, Long>? = try {
        val text = prefs().getString(SecureStrings.s("prefs_key"), null) ?: return null
        val raw = deobfuscate(machineCode, Base64.decode(text, Base64.NO_WRAP))
        Pair(CryptoUtils.unpackU64(raw.copyOfRange(0, 8)),
             CryptoUtils.unpackU64(raw.copyOfRange(8, 16)))
    } catch (t: Throwable) {
        null // undecipherable store: treat as absent (license file remains authoritative)
    }

    private fun writePrefs(machineCode: String, lastSeen: Long, rollbacks: Long) {
        try {
            val blob = obfuscate(machineCode,
                CryptoUtils.packU64(lastSeen) + CryptoUtils.packU64(rollbacks))
            prefs().edit()
                .putString(SecureStrings.s("prefs_key"),
                    Base64.encodeToString(blob, Base64.NO_WRAP))
                .apply()
        } catch (t: Throwable) {
            // best effort — the license file store survives
        }
    }

    private fun decoyFile(): File = File(context.cacheDir, SecureStrings.s("decoy_name"))

    private fun readDecoy(machineCode: String): Pair<Long, Long>? = try {
        val f = decoyFile()
        if (!f.exists()) return null
        val raw = deobfuscate(machineCode, f.readBytes())
        Pair(CryptoUtils.unpackU64(raw.copyOfRange(0, 8)),
             CryptoUtils.unpackU64(raw.copyOfRange(8, 16)))
    } catch (t: Throwable) {
        null
    }

    private fun writeDecoy(machineCode: String, lastSeen: Long, rollbacks: Long) {
        try {
            val blob = obfuscate(machineCode,
                CryptoUtils.packU64(lastSeen) + CryptoUtils.packU64(rollbacks))
            decoyFile().writeBytes(blob)
        } catch (t: Throwable) {
            // best effort
        }
    }

    // ------------------------------------------------------------ API
    fun now(): Long = System.currentTimeMillis() / 1000

    /** Clear/re-seed all stores (fresh activation or deactivation). */
    fun resetStores(machineCode: String, lastSeen: Long) {
        writePrefs(machineCode, lastSeen, 0)
        writeDecoy(machineCode, lastSeen, 0)
    }

    /** Mid-session clock-change detection; true == clean. Call periodically
     *  (the anti-debug watchdog already runs; LicenseClient calls this on
     *  every verification). */
    fun sessionCheck(): Boolean {
        val wall = System.currentTimeMillis() / 1000.0
        val tick = SystemClock.elapsedRealtime() / 1000.0
        val sw = sessionWall
        val st = sessionTick
        if (sw == null || st == null) {
            sessionWall = wall; sessionTick = tick
            return true
        }
        val wallDelta = wall - sw
        val tickDelta = tick - st
        sessionWall = wall; sessionTick = tick
        // Wall clock rewound while the monotonic clock advanced.
        return !(wallDelta < -1.0 && tickDelta > 1.0)
    }

    /** Full anti-rollback evaluation (see class docstring). */
    fun evaluate(machineCode: String, licenseLastSeen: Long, licenseRollbacks: Long,
                 allowance: Int): ClockDecision {
        val toleranceSeconds = config.clockToleranceHours * 3600L
        val stored = listOfNotNull(readPrefs(machineCode), readDecoy(machineCode))
        var lastSeen = maxOf(licenseLastSeen,
            *stored.map { it.first }.toLongArray())
        var rollbacks = maxOf(licenseRollbacks,
            *stored.map { it.second }.toLongArray())
        val now = now()

        var rolledBack = false
        var ok: Boolean
        if (now < lastSeen - toleranceSeconds) {
            rollbacks += 1
            rolledBack = true
            ok = rollbacks <= allowance
        } else {
            ok = true
            lastSeen = maxOf(now, lastSeen)
        }
        writePrefs(machineCode, lastSeen, rollbacks)   // persist even on failure —
        writeDecoy(machineCode, lastSeen, rollbacks)   // the evidence survives
        return ClockDecision(ok, lastSeen, rollbacks, rolledBack)
    }
}
