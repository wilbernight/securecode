package com.securecode.protection

import java.io.File

/**
 * Cross-platform conformance self-test — consumes sdks/vectors.json (the
 * SAME fixed vectors every platform SDK ships) and proves byte-exact wire
 * compatibility: Base32 codec, canonical JSON, fingerprint digests,
 * full serial verification (with the demo public key), Ed25519 (valid +
 * tampered) and HKDF machine-key derivation.
 *
 * Runs on the JVM (gradle :securecode-sdk:test writes
 * build/securecode-selftest.json) and inside any app for on-device spot
 * checks. Validate a report with:
 *
 *     python -m tests.cross_platform_vectors --check <report.json>
 */
object SecureCodeSelfTest {

    data class Report(val allOk: Boolean, val results: List<Entry>)

    data class Entry(val name: String, val ok: Boolean, val detail: String = "")

    /** Run all vector checks against the JSON text of sdks/vectors.json. */
    fun run(vectorsJson: String): Report {
        @Suppress("UNCHECKED_CAST")
        val vectors = try {
            WireJson.parse(vectorsJson) as Map<String, Any?>
        } catch (t: Throwable) {
            return Report(false, listOf(Entry("parse-vectors", false, "${t.message}")))
        }
        val results = ArrayList<Entry>()

        fun check(name: String, ok: Boolean, detail: String = "") {
            results.add(Entry(name, ok, detail))
        }

        fun hex(b: ByteArray) = CryptoUtils.toHex(b)

        fun asLong(v: Any?): Long = (v as? Long) ?: ((v as? Int)?.toLong() ?: 0L)
        @Suppress("UNCHECKED_CAST")
        fun asMap(v: Any?): Map<String, Any?> = (v as? Map<String, Any?>) ?: emptyMap()
        @Suppress("UNCHECKED_CAST")
        fun asList(v: Any?): List<Any?> = (v as? List<Any?>) ?: emptyList()

        // ---------------------------------------------------------- base32
        for ((i, case) in (vectors["base32"] as? List<*> ?: emptyList()).withIndex()) {
            val c = asMap(case)
            val data = CryptoUtils.fromHex(c["hex"].toString())
            val text = c["text"].toString()
            check("base32[$i].encode", Base32.encode(data) == text,
                "got ${Base32.encode(data)}")
            check("base32[$i].decode", Base32.decode(text).contentEquals(data))
            val repaired = c["repaired"]
            if (repaired != null) {
                check("base32[$i].repair", Base32.decode(repaired.toString())
                    .contentEquals(data))
            }
        }

        // ---------------------------------------------------- fingerprint
        for ((i, case) in (vectors["fingerprint"] as? List<*> ?: emptyList())
                .withIndex()) {
            val c = asMap(case)
            val raw = asMap(c["components"]).mapValues { (_, v) ->
                (v as? String).orEmpty()
            }
            val (mask, material) = FingerprintDigest.compute(raw)
            check("fingerprint[$i].mask", mask == asLong(c["mask"]).toInt(),
                "got $mask")
            check("fingerprint[$i].material", hex(material) == c["material_hex"].toString(),
                "got ${hex(material)}")
            check("fingerprint[$i].code",
                FingerprintDigest.materialCode(material) == c["code"].toString(),
                "got ${FingerprintDigest.materialCode(material)}")
        }

        // -------------------------------------------------- canonical JSON
        for ((i, case) in (vectors["canonical_json"] as? List<*> ?: emptyList())
                .withIndex()) {
            val c = asMap(case)
            val expected = c["canonical_hex"].toString()
            val got = hex(WireJson.canonicalBytes(c["payload"]))
            check("canonical_json[$i]", got == expected, "got $got")
        }

        // -------------------------------------------------------- serials
        for ((i, case) in (vectors["serial"] as? List<*> ?: emptyList()).withIndex()) {
            val c = asMap(case)
            val serialText = c["serial"].toString()
            try {
                val payload = parseSerialWithKey(serialText,
                    CryptoUtils.fromHex(c["public_key_hex"].toString()))
                check("serial[$i].verifies", true)
                check("serial[$i].product", payload.productId == asMap(c["payload"])["pid"].toString())
                check("serial[$i].expires", payload.expiresAt ==
                        asLong(asMap(c["payload"])["exp"]))
                // Tamper: flip a char in the body -> must fail verification.
                val flat = Base32.flatten(serialText)
                if (flat.isNotEmpty()) {
                    val badChar = if (flat.last() != 'A') 'A' else 'B'
                    val tampered = flat.dropLast(1) + badChar
                    val tamperedOk = try {
                        parseSerialWithKey(tampered,
                            CryptoUtils.fromHex(c["public_key_hex"].toString()))
                        true
                    } catch (t: Throwable) {
                        false
                    }
                    check("serial[$i].tamper-rejected", !tamperedOk)
                }
            } catch (t: Throwable) {
                check("serial[$i].verifies", false, "${t.message}")
            }
        }

        // ---------------------------------------------------------- ed25519
        for ((i, case) in (vectors["ed25519"] as? List<*> ?: emptyList()).withIndex()) {
            val c = asMap(case)
            val valid = Ed25519.verify(
                CryptoUtils.fromHex(c["public_key_hex"].toString()),
                CryptoUtils.fromHex(c["message_hex"].toString()),
                CryptoUtils.fromHex(c["signature_hex"].toString()))
            check("ed25519[$i]", valid == (c["valid"] == true),
                "got $valid, expected ${c["valid"]}")
        }

        // ------------------------------------------------------------ hkdf
        for ((i, case) in (vectors["hkdf"] as? List<*> ?: emptyList()).withIndex()) {
            val c = asMap(case)
            val key = CryptoUtils.deriveMachineKey(
                c["master"].toString().toByteArray(Charsets.US_ASCII),
                c["machine_code"].toString(),
                c["product_id"].toString(),
                c["context"].toString())
            check("hkdf[$i]", hex(key) == c["key_hex"].toString(), "got ${hex(key)}")
        }

        // ----------------------------------------------------------- summary
        return Report(results.all { it.ok }, results)
    }

    /** Run against a vectors file on disk (CLI helper). */
    fun runFile(vectorsFile: File): Report =
        run(vectorsFile.readText(Charsets.UTF_8))

    /** Report as the JSON text consumed by --check. */
    fun toJson(report: Report): String {
        val body = linkedMapOf<String, Any?>(
            "sdk" to "android",
            "all_ok" to report.allOk,
            "results" to report.results.map { linkedMapOf<String, Any?>(
                "name" to it.name, "ok" to it.ok, "detail" to it.detail) },
        )
        return WireJson.prettyPrint(body)
    }

    private fun parseSerialWithKey(serialText: String, publicKey: ByteArray): LicensePayload {
        val (body, signature) = Envelope.decode(serialText)
        @Suppress("UNCHECKED_CAST")
        val parsed = WireJson.parse(String(body, Charsets.UTF_8)) as Map<String, Any?>
        val payload = LicensePayload.fromWire(parsed)
        if (!Ed25519.verify(publicKey, body, signature)) throw SignatureException()
        return payload
    }
}
