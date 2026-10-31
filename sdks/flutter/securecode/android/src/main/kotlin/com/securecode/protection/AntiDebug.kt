package com.securecode.protection

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Debug
import android.os.Handler
import android.os.HandlerThread
import android.os.Process
import android.os.SystemClock
import java.io.File
import kotlin.random.Random

/**
 * Anti-debugging layer (Android port of target_demo/protection/
 * anti_debug.py):
 *
 *     * Debug.isDebuggerConnected / Development Settings
 *     * TracerPid in /proc/self/status (frida/gdb/ptrace attach)
 *     * release-build debuggable flag
 *     * optional emulator heuristics (OFF by default — false positives on
 *       legitimate users cost more than the marginal protection)
 *     * timing checks (SHA-256 workload anormaly detection)
 *
 * On detection: [DetectAction.EXIT] kills the process after a randomized
 * 2-8 s delay (looks like a normal crash) or [DetectAction.DEGRADE] makes
 * all licensing checks fail with a generic "damaged" message.
 */
internal class AntiDebug(private val context: Context,
                         private val config: ProtectionConfig) {

    @Volatile
    var degraded: Boolean = false
        private set

    @Volatile
    private var detected = false

    private var watchdogThread: HandlerThread? = null
    private var handler: Handler? = null
    private var timingBaselineMs: Double = 0.0

    // ------------------------------------------------------------ detection
    /** True when the environment looks clean right now. */
    fun initialScan(): Boolean {
        if (config.devModeActive()) return true
        timingBaselineMs = measureTimingWorkload()
        return scan().isEmpty
    }

    private fun scan(): List<String> {
        val findings = ArrayList<String>()
        if (Debug.isDebuggerConnected()) findings.add("jdwp")
        if ((tracerPid() ?: 0) != 0) findings.add("tracer")
        if (isDebuggable()) findings.add("debuggable")
        if (config.emulatorChecks && looksLikeEmulator()) findings.add("emulator")
        if (config.timingChecks && timingAnomaly()) findings.add("timing")
        return findings
    }

    private fun tracerPid(): Int? = try {
        File("/proc/self/status").bufferedReader().useLines { lines ->
            lines.firstOrNull { it.startsWith("TracerPid:") }
                ?.substringAfter(':')?.trim()?.toIntOrNull()
        }
    } catch (t: Throwable) {
        null
    }

    private fun isDebuggable(): Boolean =
        (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    private fun looksLikeEmulator(): Boolean {
        val fp = Build.FINGERPRINT
        return fp.startsWith("generic") || fp.contains("generic") ||
                fp.contains("emulator") || fp.contains("vbox") ||
                Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK") ||
                Build.MODEL.contains("sdk_gphone") || Build.PRODUCT.contains("sdk") ||
                Build.HARDWARE.contains("ranchu") || Build.HARDWARE.contains("goldfish")
    }

    /** SHA-256 workload of a fixed size; debugger/instrumentation hooks and
     *  single-stepping blow the runtime far above a calm baseline. */
    private fun measureTimingWorkload(): Double {
        val start = SystemClock.elapsedRealtime()
        var d = java.security.MessageDigest.getInstance("SHA-256")
        val block = ByteArray(4096) { (it % 251).toByte() }
        repeat(48) { d.digest(block) }
        return (SystemClock.elapsedRealtime() - start).toDouble()
    }

    private fun timingAnomaly(): Boolean {
        if (timingBaselineMs <= 0.0) return false
        val now = measureTimingWorkload()
        return now > timingBaselineMs * 8.0 + 150.0
    }

    // ------------------------------------------------------------ actions
    private fun onDetect() {
        if (detected) return
        detected = true
        when (config.onDetect) {
            DetectAction.DEGRADE -> degraded = true
            DetectAction.EXIT -> {
                val (minS, maxS) = config.detectDelayRangeSeconds
                val delayMs = (Random.nextInt(minS, maxS + 1) * 1000L)
                handler?.postDelayed({
                    Process.killProcess(Process.myPid())
                    Runtime.getRuntime().exit(0)
                }, delayMs) ?: run {
                    Process.killProcess(Process.myPid())
                    Runtime.getRuntime().exit(0)
                }
            }
        }
    }

    // ------------------------------------------------------------ watchdog
    /** Jittered watchdog (20-45 s by default) — mirrors the Windows
     *  client's background thread. No-op in dev mode. */
    fun startWatchdog() {
        if (config.devModeActive() || watchdogThread != null) return
        val thread = HandlerThread("sc-sync").apply { start() }
        watchdogThread = thread
        handler = Handler(thread.looper)
        scheduleNext()
    }

    private fun scheduleNext() {
        val h = handler ?: return
        val (minS, maxS) = config.watchdogIntervalSeconds
        val delayMs = Random.nextInt(minS, maxS + 1) * 1000L
        h.postDelayed({
            if (scan().isNotEmpty) onDetect()
            if (!detected || config.onDetect == DetectAction.DEGRADE) scheduleNext()
        }, delayMs)
    }

    fun stopWatchdog() {
        watchdogThread?.quitSafely()
        watchdogThread = null
        handler = null
    }
}
