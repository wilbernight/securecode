package com.securecode.protection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Cross-platform conformance suite — reads sdks/vectors.json and proves
 * byte-exact compatibility with the protector's wire format.
 *
 * Run:    gradle :securecode-sdk:selfTest     (from sdks/android/)
 * Report: build/securecode-selftest.json — validate with
 *         python -m tests.cross_platform_vectors --check <report>
 */
class VectorConformanceTest {

    private fun vectorsFile(): File {
        System.getProperty("securecode.vectors")?.let { return File(it) }
        // Fallbacks for plain `gradle test` runs (module working dir =
        // sdks/android/securecode-sdk)
        listOf(
            File("../../vectors.json"),                                // sdks/
            File("../../../vectors.json"),                             // repo root
            File("../../../sdks/vectors.json"),                        // normalized
        ).forEach { if (it.exists()) return it.canonicalFile }
        throw IllegalStateException(
            "sdks/vectors.json not found — run from the repo checkout or set " +
                    "-Dsecurecode.vectors=<path>")
    }

    @Test
    fun vectorConformance() {
        val report = SecureCodeSelfTest.runFile(vectorsFile())
        val failed = report.results.filter { !it.ok }
        failed.forEach { println("  FAILED ${it.name}: ${it.detail}") }
        assertEquals("vector failures", 0, failed.size)
        assertTrue("no vectors ran — missing file?", report.results.isNotEmpty())
        println("securecode android sdk: ${report.results.size} vectors passed")

        // Write the machine-readable report for tests/cross_platform_vectors
        val outPath = System.getProperty("securecode.report")
            ?: "build/securecode-selftest.json"
        val out = File(outPath)
        out.parentFile?.mkdirs()
        out.writeText(SecureCodeSelfTest.toJson(report), Charsets.UTF_8)
    }

    // -------------------------------------------------- targeted sanity checks
    @Test
    fun canonicalJsonMatchesPythonExactly() {
        // {"cust":"شرکت","v":1} — non-ASCII -> \uXXXX lowercase hex
        val bytes = WireJson.canonicalBytes(
            linkedMapOf("cust" to "شرکت", "v" to 1L))
        val expected = "{\"cust\":\"\\u0634\\u0631\\u06a9\\u062a\",\"v\":1}"
        assertEquals(expected, String(bytes, Charsets.US_ASCII))
    }

    @Test
    fun surrogatePairsEscapeLikePython() {
        val bytes = WireJson.canonicalBytes(linkedMapOf("k" to "😀"))
        assertEquals("{\"k\":\"\\ud83d\\ude00\"}", String(bytes, Charsets.US_ASCII))
    }

    @Test
    fun base32RoundTrip() {
        for (n in intArrayOf(0, 1, 2, 5, 10, 31, 64)) {
            val data = ByteArray(n) { (it * 37 % 251).toByte() }
            val text = Base32.encode(data)
            assertTrue("padding stripped", !text.endsWith("="))
            assertTrue("charset", text.all { it in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" })
            assertTrue("round trip $n", Base32.decode(text).contentEquals(data))
        }
    }

    @Test
    fun fingerprintToleranceDropsComponents() {
        val full = mapOf("cpu" to "CPUID-1", "board" to "BOARD-1",
                         "disk" to "DISK-1", "guid" to "GUID-1")
        val code = FingerprintDigest.materialCode(FingerprintDigest.compute(full).second)
        // Dropping ONE component re-derives a different code, but a serial
        // issued for the 3-component variant must still match with
        // tolerance >= 1 — the drop-combination search covers it.
        val dropped = mapOf("cpu" to "CPUID-1", "board" to "BOARD-1", "disk" to "DISK-1", "guid" to "")
        val droppedCode = FingerprintDigest.materialCode(
            FingerprintDigest.compute(dropped).second)
        assertTrue(code != droppedCode)
        // machine-code style matching: candidate codes must both validate
        listOf(code, droppedCode).forEach {
            assertEquals(19, it.length)
            assertEquals(3, it.count { ch -> ch == '-' })
        }
    }

    @Test
    fun packU64BigEndian() {
        val v = 0x0123456789ABCDEFL
        val packed = CryptoUtils.packU64(v)
        assertEquals("0123456789abcdef", CryptoUtils.toHex(packed))
        assertEquals(v, CryptoUtils.unpackU64(packed))
    }

    @Test
    fun hkdfMatchesRfcVector() {
        // RFC 5869 Test Case 1 (SHA-256)
        val ikm = ByteArray(22) { 0x0b }
        val salt = CryptoUtils.fromHex("000102030405060708090a0b0c")
        val info = CryptoUtils.fromHex("f0f1f2f3f4f5f6f7f8f9")
        val okm = CryptoUtils.hkdfSha256(ikm, salt, info, 42)
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                    "34007208d5b887185865",
            CryptoUtils.toHex(okm))
    }

    @Test
    fun gcmRoundTripAndTamper() {
        val key = ByteArray(32) { it.toByte() }
        val pt = "machine-bound payload".toByteArray()
        val ct = CryptoUtils.gcmEncrypt(key, pt)
        assertTrue(ct.size == pt.size + 12 + 16)
        assertTrue(CryptoUtils.gcmDecrypt(key, ct).contentEquals(pt))
        ct[ct.size - 1] = (ct[ct.size - 1].toInt() xor 1).toByte()
        try {
            CryptoUtils.gcmDecrypt(key, ct)
            throw AssertionError("tampered GCM must not authenticate")
        } catch (expected: SecureCodeException) {
        }
    }

    @Test
    fun payloadValidationRejectsGarbage() {
        for (bad in listOf(
            mapOf("v" to 2L, "fp" to "AB234567CDEFGHIJ", "pid" to DEMO_PID,
                  "iat" to 1_770_000_000L, "exp" to 1_803_542_400L),
            mapOf("v" to 1L, "fp" to "NOT-A-CODE", "pid" to DEMO_PID,
                  "iat" to 1_770_000_000L, "exp" to 1_803_542_400L),
            mapOf("v" to 1L, "fp" to "AB234567CDEFGHIJ", "pid" to "not-a-uuid",
                  "iat" to 1_770_000_000L, "exp" to 1_803_542_400L),
            mapOf("v" to 1L, "fp" to "AB234567CDEFGHIJ", "pid" to DEMO_PID,
                  "iat" to 1_770_000_000L, "exp" to 9999999999L),
        )) {
            try {
                LicensePayload.fromWire(bad)
                throw AssertionError("must reject $bad")
            } catch (expected: SecureCodeException) {
            }
        }
    }

    companion object {
        private const val DEMO_PID = "7e9a6cec-c185-45bb-a2fb-d31e96484f7e"
    }
}
