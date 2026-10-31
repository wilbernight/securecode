package com.securecode.protection

import android.content.Context
import java.io.File

/**
 * The offline license client — a faithful port of target_demo/protection/
 * license_client.py:
 *
 *     ACTIVATION (user pastes serial)
 *         1. Decode Base32 envelope, split payload || 64-byte Ed25519 sig
 *         2. Verify the signature against the EMBEDDED public key
 *         3. Parse + structurally validate the payload; check product id
 *         4. Compare this device's fingerprint (with tolerance) -> lock
 *         5. issued_at sanity (future-dated serial => clock problem)
 *         6. expires_at check (expired serials are refused)
 *         7. Optional signed revocation blacklist check (by nonce)
 *         8. Write the encrypted local license file (AES-256-GCM,
 *            machine-bound key) into the app-private data dir
 *         9. Seed the clock-guard stores
 *
 *     EVERY LAUNCH (verifyInstalled, 100% offline)
 *         1. Read + decrypt the local license file (machine-bound key)
 *         2. Re-verify the Ed25519 signature of the STORED serial
 *         3. Re-check fingerprint, expiry
 *         4. Clock-guard evaluation (multi-store rollback watermark)
 *         5. Re-read the signed blacklist if present
 *         6. Update last-seen watermark everywhere
 *
 *     MACHINE TRANSFER (fully offline, signed files)
 *         makeDeactivationRequest() / deactivateWithPermit() — the vendor
 *         validates the request, issues a signed permit, the OLD device
 *         consumes it (wipe + receipt), the NEW device activates with a
 *         NEW serial.
 *
 * All methods perform small local file I/O + cryptography — call them from
 * a background thread (see the platform README).
 */
class LicenseClient internal constructor(
    private val context: Context,
    private val config: ProtectionConfig,
    private val antiDebug: AntiDebug?,
    private val clockGuard: ClockGuard?,
) {

    private var machineCodeCache: String? = null
    private var fileKeyCache: ByteArray? = null
    private var lazyClock: ClockGuard? = null
    private val clock: ClockGuard
        get() {
            clockGuard?.let { return it }
            if (lazyClock == null) lazyClock = ClockGuard(context, config)
            return lazyClock!!
        }

    constructor(context: Context, config: ProtectionConfig) : this(
        context.applicationContext, config, null, null)

    companion object {
        /** Size caps before reading local artifacts (resource-exhaustion
         * hardening: a dropped multi-GB file must fail fast with a clean
         * DAMAGED/malformed state, never as an OOM crash). Real sizes:
         * license ~2 KB, permit ~1 KB; a legit 100k-entry blacklist is
         * ~4-5 MB, hence the headroom. Mirrors the Python client. */
        const val MAX_LICENSE_BYTES = 1L shl 20        // 1 MiB
        const val MAX_BLACKLIST_BYTES = 16L shl 20     // 16 MiB
        const val MAX_PERMIT_BYTES = 1L shl 20         // 1 MiB
    }

    // ================================================================ helpers
    /** This device's machine code "XXXX-XXXX-XXXX-XXXX" (cached). */
    fun machineCode(): String {
        machineCodeCache?.let { return it }
        val code = Fingerprint.machineCode(context, config)
        machineCodeCache = code
        return code
    }

    private fun publicKey(): ByteArray = config.publicKey

    private fun fileKey(): ByteArray {
        fileKeyCache?.let { return it }
        val key = CryptoUtils.deriveMachineKey(
            SecureStrings.bytes("license_master"),
            machineCode(), config.productId, "license-file-v1")
        fileKeyCache = key
        return key
    }

    // ================================================================ serials
    /** Decode + SIGNATURE-VERIFY a serial.
     *  @throws SecureCodeException malformed structure
     *  @throws SignatureException bad signature */
    @Throws(SecureCodeException::class, SignatureException::class)
    fun parseSerial(serialText: String): LicensePayload {
        val (body, signature) = Envelope.decode(serialText)
        val parsed = try {
            WireJson.parse(String(body, Charsets.UTF_8))
        } catch (e: SecureCodeException) {
            throw SecureCodeException("payload is not JSON: ${e.message}")
        }
        @Suppress("UNCHECKED_CAST")
        val payload = LicensePayload.fromWire(parsed as? Map<String, Any?>
            ?: throw SecureCodeException("payload is not a JSON object"))
        if (!Ed25519.verify(publicKey(), body, signature)) {
            throw SignatureException()
        }
        return payload
    }

    // ================================================================ blacklist
    private fun loadBlacklist(): Set<String> {
        val file: File = config.blacklistFile(context)
        if (!file.exists()) return emptySet()
        if (file.length() > MAX_BLACKLIST_BYTES) return emptySet()
        return try {
            val (body, signature) = Envelope.decode(
                String(file.readBytes(), Charsets.UTF_8))
            if (!Ed25519.verify(publicKey(), body, signature)) return emptySet()
            @Suppress("UNCHECKED_CAST")
            val data = WireJson.parse(String(body, Charsets.UTF_8))
                    as? Map<String, Any?> ?: return emptySet()
            if (data["v"] != 1L) return emptySet()
            @Suppress("UNCHECKED_CAST")
            (data["revoked"] as? List<Any?>)?.map { it.toString() }?.toSet()
                ?: emptySet()
        } catch (t: Throwable) {
            // Corrupt/forged blacklist is IGNORED (never brick the app on a
            // bad file) — but a correctly signed one always applies.
            emptySet()
        }
    }

    // ================================================================ activation
    fun activate(serialText: String): ActivationResult {
        val serial = Base32.flatten(serialText) // normalized storage form (no dashes)
        if (serial.isEmpty()) {
            return ActivationResult(false, LicenseState.MISSING,
                SecureStrings.s("msg_malformed"))
        }
        val payload: LicensePayload = try {
            parseSerial(serial)
        } catch (e: SignatureException) {
            return ActivationResult(false, LicenseState.INVALID,
                SecureStrings.s("msg_invalid"))
        } catch (e: SecureCodeException) {
            return ActivationResult(false, LicenseState.MISSING,
                SecureStrings.s("msg_malformed"))
        }

        if (payload.productId != config.productId) {
            return ActivationResult(false, LicenseState.INVALID,
                SecureStrings.s("msg_product"))
        }

        if (!Fingerprint.matches(context, config, payload.fingerprint,
                payload.tolerance)) {
            return ActivationResult(false, LicenseState.WRONG_MACHINE,
                SecureStrings.s("msg_other_machine"))
        }

        val now = System.currentTimeMillis() / 1000
        if (payload.issuedAt - now > config.clockToleranceHours * 3600L) {
            return ActivationResult(false, LicenseState.CLOCK_TAMPERED,
                SecureStrings.s("msg_future"))
        }
        if (!payload.isLifetime && now >= payload.expiresAt) {
            return ActivationResult(false, LicenseState.EXPIRED,
                SecureStrings.s("msg_expired"))
        }

        if (payload.nonce.isNotEmpty() && payload.nonce in loadBlacklist()) {
            return ActivationResult(false, LicenseState.REVOKED,
                SecureStrings.s("msg_revoked"))
        }

        writeLicenseFile(LicenseRecord(
            serial = serial,
            payload = payload.toWire(),
            activatedAt = now,
            lastSeen = now,
            rollbacks = 0,
            machineCode = machineCode(),
        ))
        clock.resetStores(machineCode(), now)
        return ActivationResult(true, LicenseState.VALID, "", payload)
    }

    // ================================================================ verification
    fun verifyInstalled(): LicenseStatus = verifyInstalled(false)

    fun verifyInstalled(degraded: Boolean): LicenseStatus {
        if (degraded) {
            // Silent degrade requested by the anti-RE layer: generic damage
            // message, no hint about the real reason.
            return LicenseStatus(LicenseState.DEGRADED,
                SecureStrings.s("msg_damaged"))
        }

        val record: LicenseRecord = try {
            readLicenseFile()
        } catch (t: LicenseMissingException) {
            return LicenseStatus(LicenseState.MISSING,
                SecureStrings.s("msg_not_installed"))
        } catch (t: Throwable) {
            return LicenseStatus(LicenseState.DAMAGED,
                SecureStrings.s("msg_damaged"))
        }

        // 1) Re-verify the STORED serial signature on every launch.
        val payload: LicensePayload
        try {
            payload = parseSerial(record.serial)
        } catch (e: SignatureException) {
            return LicenseStatus(LicenseState.INVALID, SecureStrings.s("msg_invalid"))
        } catch (e: SecureCodeException) {
            return LicenseStatus(LicenseState.DAMAGED, SecureStrings.s("msg_damaged"))
        }

        // 2) Machine binding.
        if (record.machineCode != machineCode() ||
            !Fingerprint.matches(context, config, payload.fingerprint, payload.tolerance)) {
            return LicenseStatus(LicenseState.WRONG_MACHINE,
                SecureStrings.s("msg_other_machine"))
        }

        // 3) Expiry.
        val now = System.currentTimeMillis() / 1000
        if (!payload.isLifetime && now >= payload.expiresAt) {
            return LicenseStatus(LicenseState.EXPIRED, SecureStrings.s("msg_expired"),
                payload)
        }

        // 4) Anti-clock-rollback (allowance comes from the SIGNED payload).
        val decision = clock.evaluate(
            machineCode(),
            licenseLastSeen = record.lastSeen,
            licenseRollbacks = record.rollbacks,
            allowance = payload.rollbackAllowance)
        record.lastSeen = decision.lastSeen
        record.rollbacks = decision.rollbacks
        if (!decision.ok) {
            return LicenseStatus(LicenseState.CLOCK_TAMPERED,
                SecureStrings.s("msg_clock"), payload)
        }

        // 5) Revocation blacklist (re-read every launch).
        if (payload.nonce.isNotEmpty() && payload.nonce in loadBlacklist()) {
            return LicenseStatus(LicenseState.REVOKED, SecureStrings.s("msg_revoked"),
                payload)
        }

        // 6) Persist the watermark back into the authenticated file.
        writeLicenseFile(record)

        return LicenseStatus(LicenseState.VALID, "", payload,
            payload.secondsLeft(now))
    }

    // ================================================================ transfer
    /** Export the (signed) serial + machine code for a device transfer. */
    fun makeDeactivationRequest(path: File): File {
        val record = readLicenseFile()
        val nonce = (record.payload["n"] as? String).orEmpty()
        val data = linkedMapOf<String, Any?>(
            "format" to SecureStrings.s("deact_request_format"),
            "version" to 1,
            "product_id" to config.productId,
            "machine_code" to machineCode(),
            "serial" to record.serial,
            "nonce" to nonce,
            "created" to System.currentTimeMillis() / 1000,
        )
        path.parentFile?.mkdirs()
        path.writeText(WireJson.prettyPrint(data), Charsets.UTF_8)
        return path
    }

    /** Consume the vendor's signed transfer permit on the OLD device. */
    fun deactivateWithPermit(permitFile: File): Pair<Boolean, String> {
        if (permitFile.length() > MAX_PERMIT_BYTES) {
            return Pair(false, "Permit file is malformed.")
        }
        val permit: Map<String, Any?> = try {
            val (body, signature) = Envelope.decode(
                permitFile.readText(Charsets.UTF_8).trim())
            if (!Ed25519.verify(publicKey(), body, signature)) {
                return Pair(false, "Permit signature is invalid.")
            }
            @Suppress("UNCHECKED_CAST")
            WireJson.parse(String(body, Charsets.UTF_8)) as? Map<String, Any?>
                ?: return Pair(false, "Permit is malformed.")
        } catch (t: Throwable) {
            return Pair(false, "Permit file is malformed.")
        }
        if (permit["v"] != 1L ||
            permit["action"] != SecureStrings.s("deact_permit_action")) {
            return Pair(false, "Permit is not a transfer permit.")
        }
        val record = try {
            readLicenseFile()
        } catch (t: LicenseMissingException) {
            return Pair(false, "No license is installed on this device.")
        } catch (t: Throwable) {
            return Pair(false, "The local license file is damaged.")
        }
        if (permit["old_nonce"] != record.payload["n"]) {
            return Pair(false, "Permit does not match the installed serial.")
        }

        // Wipe license + clock evidence, keep a receipt file.
        config.licenseFile(context).delete()
        clock.resetStores(machineCode(), 0)
        val receipt = File(config.dataDir(context), SecureStrings.s("receipt_name"))
        receipt.parentFile?.mkdirs()
        val nonce = permit["old_nonce"]?.toString() ?: ""
        receipt.writeText(WireJson.prettyPrint(linkedMapOf(
            "format" to "securecode-deactivation-receipt",
            "version" to 1,
            "nonce" to nonce,
            "deactivated_at" to System.currentTimeMillis() / 1000,
        )), Charsets.UTF_8)
        return Pair(true, "License removed. You can now activate on the new device.")
    }

    // ================================================================ license file I/O
    private class LicenseMissingException : RuntimeException()

    private data class LicenseRecord(
        val serial: String,
        val payload: Map<String, Any?>,
        val activatedAt: Long,
        var lastSeen: Long,
        var rollbacks: Long,
        val machineCode: String,
        val blacklistVer: Long = 0,
    )

    private val licenseMagic = "SCLIC1".toByteArray(Charsets.US_ASCII)

    private fun readLicenseFile(): LicenseRecord {
        val file = config.licenseFile(context)
        if (!file.exists()) throw LicenseMissingException()
        if (file.length() > MAX_LICENSE_BYTES) {
            throw SecureCodeException("license file too large")
        }
        val blob = file.readBytes()
        if (blob.size < licenseMagic.size ||
            !blob.copyOfRange(0, licenseMagic.size).contentEquals(licenseMagic)) {
            throw SecureCodeException("bad magic")
        }
        val plain = try {
            CryptoUtils.gcmDecrypt(fileKey(),
                blob.copyOfRange(licenseMagic.size, blob.size))
        } catch (t: Throwable) {
            throw SecureCodeException("license file unreadable")
        }
        @Suppress("UNCHECKED_CAST")
        val data = WireJson.parse(String(plain, Charsets.UTF_8))
                as? Map<String, Any?> ?: throw SecureCodeException("bad record")
        val payload = data["payload"] as? Map<String, Any?> ?: emptyMap()
        return LicenseRecord(
            serial = data["serial"].toString(),
            payload = payload,
            activatedAt = (data["activated_at"] as? Long) ?: 0L,
            lastSeen = (data["last_seen"] as? Long) ?: 0L,
            rollbacks = (data["rollbacks"] as? Long) ?: 0L,
            machineCode = data["machine_code"].toString(),
        )
    }

    private fun writeLicenseFile(record: LicenseRecord) {
        val dir = config.dataDir(context)
        dir.mkdirs()
        val plain = WireJson.canonicalBytes(linkedMapOf(
            "v" to 1L,
            "serial" to record.serial,
            "payload" to record.payload,
            "activated_at" to record.activatedAt,
            "last_seen" to record.lastSeen,
            "rollbacks" to record.rollbacks,
            "machine_code" to record.machineCode,
            "blacklist_ver" to record.blacklistVer,
        ))
        val blob = licenseMagic + CryptoUtils.gcmEncrypt(fileKey(), plain)
        val file = config.licenseFile(context)
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(blob)
        if (!tmp.renameTo(file)) {
            file.delete()
            if (!tmp.renameTo(file)) {
                throw SecureCodeException("license file unwritable")
            }
        }
    }

    // ================================================================ utilities
    /** Customer string of the locally installed license (or ""). */
    fun installedCustomer(): String = try {
        ((readLicenseFile().payload["cust"] as? String) ?: "")
    } catch (t: Throwable) {
        ""
    }

    /** Expiry unix timestamp of the installed license (or 0). */
    fun installedExpiresAt(): Long = try {
        (readLicenseFile().payload["exp"] as? Long) ?: 0L
    } catch (t: Throwable) {
        0L
    }
}

/** Result of activate(). */
data class ActivationResult(
    val ok: Boolean,
    val state: LicenseState,
    val message: String,
    val payload: LicensePayload? = null,
)

/** Result of verifyInstalled(). */
data class LicenseStatus(
    val state: LicenseState,
    val message: String,
    val payload: LicensePayload? = null,
    val secondsLeft: Long = -1,
) {
    val isValid: Boolean get() = state == LicenseState.VALID
}
