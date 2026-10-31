package com.securecode.protection

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Machine-bound key derivation + symmetric crypto (mirrors
 * target_demo/protection/crypto_utils.py).
 *
 * Every local artifact (license file, clock stores) is encrypted with a key
 * derived from:
 *
 *     HKDF-SHA256( ikm  = embedded_master_secret || "|" || machine_code,
 *                  salt = product_id,  info = purpose_context )
 *
 * The machine code participates in the IKM, so artifacts are bound to the
 * device: copying license.dat to another device fails AES-GCM authentication
 * before any license logic runs. The master secret lives only in the
 * obfuscated string layer (SecureStrings) — regenerate per product
 * (sdks/gen_strings.py).
 */
internal object CryptoUtils {

    /** RFC 5869 HKDF-SHA256 (extract + expand). */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // extract
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        // expand
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = ByteArray(length)
        var t = ByteArray(0)
        var counter = 1
        var filled = 0
        while (filled < length) {
            mac.reset()
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            val block = mac.doFinal()
            val n = minOf(block.size, length - filled)
            System.arraycopy(block, 0, out, filled, n)
            t = block
            filled += n
            counter++
        }
        return out
    }

    /** Purpose-bound machine key — identical construction to the Windows
     *  client (crypto_utils.derive_machine_key). */
    fun deriveMachineKey(master: ByteArray, machineCode: String, productId: String,
                         context: String): ByteArray {
        val ikm = master + "|".toByteArray(Charsets.US_ASCII) +
                machineCode.toByteArray(Charsets.US_ASCII)
        return hkdfSha256(
            ikm,
            salt = productId.toByteArray(Charsets.US_ASCII),
            info = context.toByteArray(Charsets.UTF_8),
            length = 32)
    }

    // ------------------------------------------------------------ AES-GCM
    /** AES-256-GCM with a fresh random 12-byte nonce prepended. */
    fun gcmEncrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"),
            GCMParameterSpec(128, nonce))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return nonce + cipher.doFinal(plaintext)
    }

    /** Inverse of [gcmEncrypt]; throws on any authentication failure. */
    fun gcmDecrypt(key: ByteArray, blob: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray {
        if (blob.size < 12) throw SecureCodeException("ciphertext too short")
        val nonce = blob.copyOfRange(0, 12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"),
            GCMParameterSpec(128, nonce))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return try {
            cipher.doFinal(blob, 12, blob.size - 12)
        } catch (e: Exception) {
            throw SecureCodeException("decryption failed (tampered or wrong key): ${e.message}")
        }
    }

    // ------------------------------------------------------------ AES-CTR
    /**
     * Deterministic AES-256-CTR "at-rest" obfuscation for the clock stores —
     * byte-for-byte the same construction as the Windows client
     * (crypto_utils.obfuscate): IV = SHA256("sc-obf-iv:" + context)[:16],
     * deterministic on purpose so silent re-writes are idempotent.
     */
    fun ctrCrypt(machineCode: String, productId: String, context: String,
                 master: ByteArray, data: ByteArray): ByteArray {
        val key = deriveMachineKey(master, machineCode, productId, context)
        val d = MessageDigest.getInstance("SHA-256")
        d.update("sc-obf-iv:".toByteArray(Charsets.US_ASCII))
        d.update(context.toByteArray(Charsets.UTF_8))
        val iv = d.digest().copyOfRange(0, 16)
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return cipher.doFinal(data) // CTR: encrypt == decrypt
    }

    // ------------------------------------------------------------ utilities
    fun packU64(value: Long): ByteArray {
        require(value >= 0) { "pack_u64 expects a non-negative value" }
        return byteArrayOf(
            (value ushr 56).toByte(), (value ushr 48).toByte(),
            (value ushr 40).toByte(), (value ushr 32).toByte(),
            (value ushr 24).toByte(), (value ushr 16).toByte(),
            (value ushr 8).toByte(), value.toByte())
    }

    fun unpackU64(data: ByteArray): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (data[i].toLong() and 0xFF)
        return v
    }

    /** Best-effort zeroization (Layer 5 hygiene). */
    fun secureZero(buffer: ByteArray?) {
        buffer?.fill(0)
    }

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    /** Lowercase hex (no sign-extension issues with negative bytes). */
    fun toHex(data: ByteArray): String {
        val sb = StringBuilder(data.size * 2)
        for (b in data) {
            val v = b.toInt() and 0xFF
            sb.append("0123456789abcdef"[v ushr 4])
            sb.append("0123456789abcdef"[v and 0x0F])
        }
        return sb.toString()
    }

    fun fromHex(hex: String): ByteArray {
        val clean = if (hex.length % 2 == 0) hex else "0$hex"
        return ByteArray(clean.length / 2) { i ->
            ((Character.digit(clean[2 * i], 16) shl 4)
                    or Character.digit(clean[2 * i + 1], 16)).toByte()
        }
    }

    private operator fun ByteArray.plus(other: ByteArray): ByteArray {
        val out = ByteArray(size + other.size)
        System.arraycopy(this, 0, out, 0, size)
        System.arraycopy(other, 0, out, size, other.size)
        return out
    }
}
