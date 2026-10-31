package com.securecode.protection

/**
 * RFC 4648 Base32 codec — the ONLY alphabet Base32 uses (no 0/O or 1/l
 * ambiguity), matching Python's base64.b32encode/b32decode exactly.
 *
 * Decoders accept any casing, dashes and whitespace, and repair the digits
 * Base32 never uses (0/1/8/9 — customers sometimes swap O/0 or I/1).
 */
internal object Base32 {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    // value of every allowed char (both cases); -1 = not in alphabet
    private val VALUES = IntArray(128) { -1 }.also { arr ->
        ALPHABET.forEachIndexed { i, c ->
            arr[c.code] = i
            arr[c.code + 32] = i // lowercase
        }
    }

    /** Encode bytes as unpadded uppercase Base32 (identical to Python's
     *  b32encode(...).rstrip('=')). */
    fun encode(data: ByteArray): String {
        val out = StringBuilder((data.size * 8 + 4) / 5)
        var i = 0
        while (i + 5 <= data.size) {
            val chunk = ((data[i].toLong() and 0xFF) shl 32) or
                    ((data[i + 1].toLong() and 0xFF) shl 24) or
                    ((data[i + 2].toLong() and 0xFF) shl 16) or
                    ((data[i + 3].toLong() and 0xFF) shl 8) or
                    (data[i + 4].toLong() and 0xFF)
            for (shift in 7 downTo 0) {
                out.append(ALPHABET[((chunk shr (5 * shift)) and 0x1F).toInt()])
            }
            i += 5
        }
        val rem = data.size - i
        if (rem > 0) {
            var chunk = 0L
            for (j in 0 until rem) {
                chunk = (chunk shl 8) or (data[i + j].toLong() and 0xFF)
            }
            chunk = chunk shl ((5 - rem) * 8) // align as if 5 bytes were present
            val chars = rem * 8 / 5 // 1->1, 2->3, 3->4, 4->6
            for (shift in 7 downTo (8 - chars)) {
                out.append(ALPHABET[((chunk shr (5 * shift)) and 0x1F).toInt()])
            }
        }
        return out.toString()
    }

    /** Decode Base32 text (any casing/spacing/dashes; strips 0/1/8/9).
     *  Throws [SecureCodeException] — never a platform-specific error. */
    fun decode(text: String): ByteArray {
        val compact = flattenRepair(text)
        val out = ByteArray(compact.length * 5 / 8)
        var buffer = 0
        var bits = 0
        var idx = 0
        for (c in compact) {
            val value = if (c.code < 128) VALUES[c.code] else -1
            if (value < 0) {
                throw SecureCodeException(
                    "serial contains characters outside Base32 alphabet")
            }
            buffer = (buffer shl 5) or value
            bits += 5
            if (bits >= 8) {
                bits -= 8
                out[idx++] = ((buffer shr bits) and 0xFF).toByte()
            }
        }
        return out
    }

    /** Uppercase + keep alphanumerics only + strip digits Base32 never uses
     *  (repair heuristic — mirrors shared/codec.py). */
    fun flattenRepair(text: String): String {
        val sb = StringBuilder(text.length)
        for (ch in text.uppercase()) {
            if (ch.isLetterOrDigit()) {
                if (ch != '0' && ch != '1' && ch != '8' && ch != '9') sb.append(ch)
            }
        }
        return sb.toString()
    }

    /** Uppercase + keep alphanumerics only (machine-code flattening). */
    fun flatten(text: String): String {
        val sb = StringBuilder(text.length)
        for (ch in text.uppercase()) if (ch.isLetterOrDigit()) sb.append(ch)
        return sb.toString()
    }

    /** Group a flat string into '-'-separated blocks of [size]. */
    fun groupBlocks(text: String, size: Int, sep: String = "-"): String {
        if (text.isEmpty()) return text
        val sb = StringBuilder()
        var i = 0
        while (i < text.length) {
            if (i > 0) sb.append(sep)
            sb.append(text, i, minOf(i + size, text.length))
            i += size
        }
        return sb.toString()
    }
}
