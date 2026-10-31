package com.securecode.protection

import android.content.Context
import android.os.Process

/**
 * Owns the background anti-RE machinery for one process — the Android port
 * of target_demo/protection.ProtectionRuntime.
 *
 * Call [bootstrap] ONCE as the very first statement of Application.onCreate()
 * (or the launcher activity); it never returns a rejected state — on hard
 * integrity failure it kills the process silently (graceful, non-obvious
 * termination by design).
 */
object ProtectionRuntime {

    fun bootstrap(context: Context, config: ProtectionConfig): Handle {
        if (config.integrityChecks && !config.devModeActive()) {
            val (ok, _) = Integrity.runChecks(context, config)
            if (!ok) {
                // Silent, non-obvious termination (documented decision).
                Process.killProcess(Process.myPid())
                Runtime.getRuntime().exit(0)
            }
        }
        val anti = AntiDebug(context, config)
        val clock = ClockGuard(context, config)
        if (config.antiDebugEnabled && !config.devModeActive()) {
            anti.initialScan()
            anti.startWatchdog()
        }
        return Handle(anti, clock, config)
    }

    /** Runtime handle for one process. */
    class Handle internal constructor(
        private val antiDebug: AntiDebug,
        val clockGuard: ClockGuard,
        private val config: ProtectionConfig,
    ) {
        /** True when anti-debug switched to silent-degrade mode — pass to
         *  LicenseClient.verifyInstalled(degraded). */
        val degraded: Boolean get() = antiDebug.degraded

        /** Stop watchdog threads on clean application exit. */
        fun shutdown() = antiDebug.stopWatchdog()

        /** Convenience: a LicenseClient wired to this runtime's clock guard
         *  (share the SAME client across the app). */
        fun licenseClient(context: Context): LicenseClient =
            LicenseClient(context, config, antiDebug, clockGuard)
    }
}
