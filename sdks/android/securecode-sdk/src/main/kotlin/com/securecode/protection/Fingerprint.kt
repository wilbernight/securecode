package com.securecode.protection

import android.annotation.SuppressLint
import android.content.Context
import android.media.MediaDrm
import android.os.Build
import android.provider.Settings
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * Device fingerprinting (client) — the Android port of
 * target_demo/protection/fingerprint.py.
 *
 * The four hash slots ("cpu"/"board"/"disk"/"guid") are filled with
 * Android-appropriate identifiers (slot names are stable hash labels, not
 * literal component types):
 *
 *     cpu   : MediaDrm Widevine device ID — hardware-backed, provisioned at
 *             factory, stable across app reinstalls AND factory resets on
 *             most devices. No permission needed.
 *     board : SSAID (Settings.Secure.ANDROID_ID) — stable per
 *             (device, signing key) since Android 8, survives
 *             uninstall/reinstall, resets on factory reset.
 *     disk  : Android Keystore EC keypair digest — OPTIONAL (off by
 *             default): adds a per-install binding (wiped on uninstall).
 *             Enable only when serials should NOT survive reinstalls.
 *     guid  : reserved (empty).
 *
 * With the default profile (cpu+board), an uninstall + reinstall produces
 * the SAME machine code, so the customer can re-activate with the SAME
 * serial — mirroring the Windows UX. tolerance=1 absorbs a factory reset
 * of the SSAID.
 */
internal object Fingerprint {

    /** Widevine modular DRM scheme UUID (official, hardcoded by the
     *  Android CDM spec — see ExoPlayer C.WIDEVINE_UUID). */
    private val WIDEVINE_UUID: UUID =
        UUID(-0x121074568629b532L, -0x5c37d8232ae2de13L)

    const val CODE_GROUP_SIZE = 4

    // ------------------------------------------------------------ collectors
    /** Raw component values for the hash slots (never exposed to callers). */
    fun collectComponents(context: Context, config: ProtectionConfig): Map<String, String> {
        val cpu = widevineId()
        val board = ssaid(context)
        val disk = if (config.useKeystoreComponent) keystoreComponent() else ""
        val guid = ""
        return mapOf("cpu" to cpu, "board" to board, "disk" to disk, "guid" to guid)
    }

    private fun widevineId(): String = try {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) return ""
        val drm = MediaDrm(WIDEVINE_UUID)
        try {
            val raw = drm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID)
            if (raw != null && raw.isNotEmpty()) {
                // Hash raw bytes -> stable, printable ASCII component.
                CryptoUtils.toHex(CryptoUtils.sha256(raw))
            } else ""
        } finally {
            @Suppress("DEPRECATION")
            runCatching { drm.close() }
        }
    } catch (t: Throwable) {
        "" // unsupported scheme / emulator without CDM -> component missing
    }

    @SuppressLint("HardwareIds")
    private fun ssaid(context: Context): String = try {
        Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: ""
    } catch (t: Throwable) {
        ""
    }

    /** EC keypair in the Android Keystore, digested to a printable value.
     *  Regenerated on reinstall -> intentionally per-install. */
    private fun keystoreComponent(): String = try {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return ""
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = SecureStrings.s("keystore_alias")
        if (!ks.containsAlias(alias)) {
            val gen = KeyPairGenerator.getInstance("EC", "AndroidKeyStore")
            gen.initialize(
                ECGenParameterSpec("secp256r1"),
                android.security.keystore.KeyGenParameterSpec.Builder(
                    alias,
                    android.security.keystore.KeyProperties.PURPOSE_SIGN or
                        android.security.keystore.KeyProperties.PURPOSE_VERIFY)
                    .build())
            gen.generateKeyPair()
        }
        val pub = ks.getCertificate(alias)?.publicKey?.encoded ?: return ""
        CryptoUtils.toHex(CryptoUtils.sha256(pub))
    } catch (t: Throwable) {
        ""
    }

    // ------------------------------------------------------------ public API
    /** This device's machine code: "XXXX-XXXX-XXXX-XXXX". */
    fun machineCode(context: Context, config: ProtectionConfig): String {
        val (_, material) = FingerprintDigest.compute(collectComponents(context, config))
        return Base32.groupBlocks(Base32.encode(material), CODE_GROUP_SIZE)
    }

    /** Bitmask of currently-present components. */
    fun machineMask(context: Context, config: ProtectionConfig): Int =
        FingerprintDigest.compute(collectComponents(context, config)).first

    /**
     * Fingerprint matching WITH hardware-change tolerance (drop-combination
     * search — mirrors the Windows client's matches()): "the customer
     * factory-reset the SSAID" is modeled by pretending each present
     * component (or pair, up to [tolerance]) went missing at serial-issue
     * time and checking whether any candidate still matches.
     */
    fun matches(context: Context, config: ProtectionConfig,
                targetCode: String, tolerance: Int): Boolean {
        val target = Base32.flatten(targetCode)
        val ours = collectComponents(context, config)
        val present = FingerprintDigest.COMPONENT_ORDER.filter { ours[it].orEmpty().isNotEmpty() }

        fun codeWithDrop(drop: Set<String>): String {
            val subset = ours.mapValues { (k, v) -> if (k in drop) "" else v }
            return Base32.encode(FingerprintDigest.compute(subset).second)
        }

        if (codeWithDrop(emptySet()) == target) return true
        val maxK = minOf(tolerance, present.size)
        for (k in 1..maxK) {
            for (drop in combinations(present, k)) {
                if (codeWithDrop(drop.toSet()) == target) return true
            }
        }
        return false
    }

    private fun <T> combinations(items: List<T>, k: Int): List<List<T>> {
        if (k == 0) return listOf(emptyList())
        if (items.size < k) return emptyList()
        val head = items.first()
        val tail = items.drop(1)
        return combinations(tail, k - 1).map { listOf(head) + it } + combinations(tail, k)
    }

    /** Fingerprint export file the customer sends the vendor (JSON, no raw
     *  hardware identifiers — privacy over email/support channels). */
    fun exportFingerprintFile(context: Context, config: ProtectionConfig,
                               path: java.io.File): java.io.File {
        val code = machineCode(context, config)
        val mask = machineMask(context, config)
        val present = FingerprintDigest.parseComponentMask(mask)
        val data = linkedMapOf<String, Any?>(
            "format" to SecureStrings.s("fp_export_format"),
            "version" to 1,
            "platform" to "android",
            "code" to code,
            "present" to present,
            "product_id" to config.productId,
            "created" to System.currentTimeMillis() / 1000,
        )
        path.parentFile?.mkdirs()
        path.writeText(WireJson.prettyPrint(data), Charsets.UTF_8)
        return path
    }
}
