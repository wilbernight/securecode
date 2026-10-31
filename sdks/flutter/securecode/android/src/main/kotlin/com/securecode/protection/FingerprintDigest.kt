package com.securecode.protection

import java.security.MessageDigest

/**
 * Hardware-fingerprint digest — the contract behind the machine code
 * "XXXX-XXXX-XXXX-XXXX" (mirrors shared/payload_schema.py EXACTLY):
 *
 *     material = mask_byte(1B) || SHA256( salt || "cpu=<v>;" || "board=<v>;"
 *                                     || "disk=<v>;" || "guid=<v>;"
 *                                     || "mask=<n>" )[:9]
 *     code     = Base32(material) -> 16 chars, displayed 4x4
 *
 * The four slot names are platform-stable hash labels: every platform SDK
 * (Windows/Android/iOS/macOS) maps ITS identifiers into the same slots,
 * so a serial issued for one code never matches another machine's code by
 * accident. The salt is a PUBLIC domain separator (anti cross-vendor
 * collisions), not a secret.
 */
internal object FingerprintDigest {

    val SALT: ByteArray = ("Secure" + "Code" + "-v1.0" + "/fp-salt")
        .toByteArray(Charsets.US_ASCII)

    val COMPONENT_ORDER = listOf("cpu", "board", "disk", "guid")

    val COMPONENT_MASK_BITS = mapOf(
        "cpu" to 0x01, "board" to 0x02, "disk" to 0x04, "guid" to 0x08)

    /** Mirrors shared.payload_schema.normalize_component: strip whitespace,
     *  strip trailing NULs (old BIOS serials), strip again, lowercase. */
    fun normalizeComponent(value: String?): String {
        if (value.isNullOrEmpty()) return ""
        return value.trim().trim('\u0000').trim().lowercase()
    }

    /** Compute (mask, 10-byte material) for a raw component mapping.
     *  Missing/empty components contribute an empty string to the hash and
     *  clear their mask bit — the tolerance mechanism relies on this. */
    fun compute(components: Map<String, String>): Pair<Int, ByteArray> {
        val d = MessageDigest.getInstance("SHA-256")
        var mask = 0
        d.update(SALT)
        for (name in COMPONENT_ORDER) {
            val norm = normalizeComponent(components[name])
            if (norm.isNotEmpty()) mask = mask or (COMPONENT_MASK_BITS[name] ?: 0)
            d.update(("$name=$norm;").toByteArray(Charsets.UTF_8))
        }
        d.update("mask=$mask".toByteArray(Charsets.US_ASCII))
        val digest = d.digest()
        val material = ByteArray(10)
        material[0] = mask.toByte()
        System.arraycopy(digest, 0, material, 1, 9)
        return Pair(mask, material)
    }

    /** Which components are present, decoded from a mask byte. */
    fun parseComponentMask(mask: Int): Map<String, Boolean> =
        COMPONENT_ORDER.associateWith { (mask and (COMPONENT_MASK_BITS[it] ?: 0)) != 0 }

    /** Full display machine code (4-char groups). */
    fun materialCode(material: ByteArray): String =
        Base32.groupBlocks(Base32.encode(material), 4)
}
