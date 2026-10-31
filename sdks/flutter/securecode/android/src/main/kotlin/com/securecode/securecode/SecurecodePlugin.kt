package com.securecode.securecode

import android.content.Context
import android.os.Handler
import android.os.Looper
import com.securecode.protection.DetectAction
import com.securecode.protection.Fingerprint
import com.securecode.protection.LicenseClient
import com.securecode.protection.LicenseState
import com.securecode.protection.ProtectionConfig
import com.securecode.protection.ProtectionRuntime
import com.securecode.protection.SecureCodeSelfTest
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.io.File
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * MethodChannel glue ("securecode/licensing") between the Dart API and the
 * SecureCode Android SDK (the same Kotlin SDK native apps use — synced in
 * from sdks/android/securecode-sdk by sdks/sync_native.py).
 *
 * All SDK work runs on a single background executor; results are posted
 * back to the main thread (the standard plugin pattern — the Dart side is
 * await-able and never blocks the UI).
 */
class SecurecodePlugin : FlutterPlugin, MethodCallHandler {

    private var appContext: Context? = null
    private var channel: MethodChannel? = null
    private var runtime: ProtectionRuntime.Handle? = null
    private var client: LicenseClient? = null
    private var config: ProtectionConfig? = null

    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        appContext = binding.applicationContext
        channel = MethodChannel(binding.binaryMessenger, "securecode/licensing").also {
            it.setMethodCallHandler(this)
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel?.setMethodCallHandler(null)
        channel = null
        try {
            runtime?.shutdown()
        } catch (_: Throwable) {
        }
        runtime = null
        client = null
        config = null
        appContext = null
        executor.shutdown()
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "init" -> runAsync(result) { init(call.arguments as? Map<*, *>); null }
            "machineCode" -> runAsync(result) { client().machineCode() }
            "activate" -> runAsync(result) {
                val serial = call.argument<String>("serial").orEmpty()
                val r = client().activate(serial)
                mapOf(
                    "ok" to r.ok,
                    "state" to r.state.name,
                    "message" to r.message,
                    "payload" to r.payload?.toWire(),
                )
            }
            "verify" -> runAsync(result) {
                val degraded = runtime?.degraded ?: false
                val s = client().verifyInstalled(degraded)
                mapOf(
                    "state" to s.state.name,
                    "message" to s.message,
                    "secondsLeft" to s.secondsLeft,
                    "payload" to s.payload?.toWire(),
                )
            }
            "degraded" -> result.success(runtime?.degraded ?: false)
            "exportFingerprint" -> runAsync(result) {
                val path = requirePath(call)
                val ctx = requireContext()
                val cfg = requireConfig()
                Fingerprint.exportFingerprintFile(
                    ctx, cfg, File(path)).absolutePath
            }
            "makeDeactivationRequest" -> runAsync(result) {
                val path = requirePath(call)
                client().makeDeactivationRequest(File(path)).absolutePath
            }
            "deactivateWithPermit" -> runAsync(result) {
                val path = requirePath(call)
                val (ok, message) = client().deactivateWithPermit(File(path))
                mapOf("ok" to ok, "message" to message)
            }
            "installedCustomer" -> runAsync(result) { client().installedCustomer() }
            "installedExpiresAt" -> runAsync(result) { client().installedExpiresAt() }
            "selfTest" -> runAsync(result) {
                val vectors = call.argument<String>("vectors").orEmpty()
                val report = SecureCodeSelfTest.run(vectors)
                mapOf(
                    "allOk" to report.allOk,
                    "results" to report.results.map {
                        mapOf("name" to it.name, "ok" to it.ok, "detail" to it.detail)
                    },
                )
            }
            "shutdown" -> runAsync(result) {
                runtime?.shutdown(); null
            }
            else -> result.notImplemented()
        }
    }

    // ---------------------------------------------------------------- helpers
    /** Validate channel arguments up front so a bad Dart call surfaces as a
     *  clear PlatformException instead of a bare NPE. */
    private fun requirePath(call: MethodCall): String =
        call.argument<String>("path")?.takeIf { it.isNotEmpty() }
            ?: throw IllegalArgumentException("path is required")

    private fun requireContext(): Context =
        appContext ?: throw IllegalStateException("plugin is not attached")

    private fun requireConfig(): ProtectionConfig =
        config ?: throw IllegalStateException("SecureCode not initialized — call initialize() first")

    private fun client(): LicenseClient =
        client ?: throw IllegalStateException("SecureCode not initialized — call initialize() first")

    private fun init(args: Map<*, *>?) {
        val ctx = appContext ?: throw IllegalStateException("no context")
        val map = args ?: throw IllegalArgumentException("config map required")
        val builder = ProtectionConfig.Builder(map["productId"].toString())
        (map["productName"] as? String)?.let { builder.productName(it) }
        (map["companyName"] as? String)?.let { builder.companyName(it) }
        (map["publicKeyHex"] as? String)?.let { builder.publicKeyHex(it) }
        (map["antiDebugEnabled"] as? Boolean)?.let { builder.antiDebugEnabled(it) }
        (map["emulatorChecks"] as? Boolean)?.let { builder.emulatorChecks(it) }
        (map["timingChecks"] as? Boolean)?.let { builder.timingChecks(it) }
        when (map["onDetect"] as? String) {
            "degrade" -> builder.onDetect(DetectAction.DEGRADE)
            "exit" -> builder.onDetect(DetectAction.EXIT)
        }
        (map["detectDelayMin"] as? Int)?.let { min ->
            val max = map["detectDelayMax"] as? Int ?: min
            builder.detectDelayRangeSeconds(minOf(min, max), maxOf(min, max))
        }
        (map["watchdogMin"] as? Int)?.let { min ->
            val max = map["watchdogMax"] as? Int ?: min
            builder.watchdogIntervalSeconds(minOf(min, max), maxOf(min, max))
        }
        (map["integrityChecks"] as? Boolean)?.let { builder.integrityChecks(it) }
        (map["expectedSignerCertSha256"] as? String)?.takeIf { it.isNotEmpty() }
            ?.let { builder.expectedSignerCertSha256(it) }
        (map["fingerprintTolerance"] as? Int)?.let { builder.fingerprintTolerance(it) }
        (map["clockToleranceHours"] as? Int)?.let { builder.clockToleranceHours(it) }
        (map["defaultRollbackAllowance"] as? Int)?.let { builder.defaultRollbackAllowance(it) }
        (map["devMode"] as? Boolean)?.let { builder.devMode(it) }
        (map["useKeystoreComponent"] as? Boolean)?.let { builder.useKeystoreComponent(it) }

        val cfg = builder.build()
        val handle = ProtectionRuntime.bootstrap(ctx, cfg)
        config = cfg
        runtime = handle
        client = handle.licenseClient(ctx)
    }

    private fun runAsync(result: Result, work: () -> Any?) {
        executor.execute {
            try {
                val value = work()
                main.post {
                    try {
                        result.success(value)
                    } catch (_: Throwable) {
                    }
                }
            } catch (t: Throwable) {
                main.post {
                    try {
                        result.error("securecode", t.message ?: "internal error", null)
                    } catch (_: Throwable) {
                    }
                }
            }
        }
    }
}
