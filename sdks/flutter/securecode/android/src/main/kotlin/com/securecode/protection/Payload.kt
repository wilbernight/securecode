package com.securecode.protection

/**
 * The signed body of a serial key (mirrors shared.payload_schema.
 * LicensePayload — same field names, same validation, byte-identical
 * canonical serialization).
 */
data class LicensePayload(
    val fingerprint: String,          // machine code "XXXX-XXXX-XXXX-XXXX"
    val productId: String,           // product UUID string (lowercase)
    val issuedAt: Long,              // unix ts (seconds)
    val expiresAt: Long,             // unix ts; 0 = lifetime
    val customer: String = "",       // free-form customer name/ID
    val nonce: String = "",          // 16-byte hex; uniqueness + revocation id
    val featureFlags: Map<String, Boolean> = emptyMap(),
    val tolerance: Int = 1,          // missing fingerprint components allowed
    val rollbackAllowance: Int = 3,  // clock rollbacks tolerated
    val version: Int = PAYLOAD_VERSION,
) {
    val isLifetime: Boolean get() = expiresAt == EXP_LIFETIME

    fun secondsLeft(now: Long): Long =
        if (isLifetime) MAX_TS - now else expiresAt - now

    // ------------------------------------------------------------ wire form
    fun toWire(): Map<String, Any?> = linkedMapOf(
        "v" to version,
        "fp" to fingerprint,
        "pid" to productId,
        "iat" to issuedAt,
        "exp" to expiresAt,
        "cust" to customer,
        "n" to nonce,
        "fl" to featureFlags,
        "tol" to tolerance,
        "rb" to rollbackAllowance,
    )

    /** Byte-exact canonical JSON (what the protector signed). */
    fun canonicalBytes(): ByteArray = WireJson.canonicalBytes(toWire())

    companion object {
        const val PAYLOAD_VERSION = 1
        const val EXP_LIFETIME = 0L
        const val MIN_TS = 1_577_836_800L   // 2020-01-01
        const val MAX_TS = 4_102_444_800L   // 2100-01-01
        private const val B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        private val UUID_DASHED = Regex(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
        private val UUID_PLAIN = Regex("^[0-9a-fA-F]{32}$")

        /** Parse + structurally validate the compact wire dict.
         *  @throws SecureCodeException on any malformed field. */
        @Suppress("UNCHECKED_CAST")
        fun fromWire(data: Map<String, Any?>): LicensePayload {
            fun req(key: String): Any? = data[key]
                ?: throw SecureCodeException("payload missing required field: '$key'")
            fun asLong(key: String, v: Any?): Long = when (v) {
                is Long -> v
                is Int -> v.toLong()
                is String -> v.toLongOrNull()
                    ?: throw SecureCodeException("payload field '$key' has invalid type")
                else -> throw SecureCodeException("payload field '$key' has invalid type")
            }
            val flagsRaw = data["fl"] as? Map<*, *>
            val flags = flagsRaw?.mapKeys { it.key.toString() }
                ?.mapValues { (_, v) -> pythonTruth(v) } ?: emptyMap()
            val payload = LicensePayload(
                version = asLong("v", req("v")).toInt(),
                fingerprint = req("fp").toString(),
                productId = req("pid").toString(),
                issuedAt = asLong("iat", req("iat")),
                expiresAt = asLong("exp", req("exp")),
                customer = (data["cust"] as? String) ?: "",
                nonce = (data["n"] as? String) ?: "",
                featureFlags = flags,
                tolerance = data["tol"]?.let { asLong("tol", it).toInt() } ?: 1,
                rollbackAllowance = data["rb"]?.let { asLong("rb", it).toInt() } ?: 3,
            )
            payload.validate()
            return payload
        }

        /** Python bool() semantics for the feature-flag coercion. */
        private fun pythonTruth(v: Any?): Boolean = when (v) {
            null -> false
            is Boolean -> v
            is Long -> v != 0L
            is Int -> v != 0
            is Double -> v != 0.0
            is String -> v.isNotEmpty()
            is List<*> -> v.isNotEmpty()
            is Map<*, *> -> v.isNotEmpty()
            else -> true
        }
    }

    // ------------------------------------------------------------ validation
    fun validate() {
        if (version != PAYLOAD_VERSION) {
            throw SecureCodeException("unsupported payload version $version")
        }
        if (expiresAt != EXP_LIFETIME && expiresAt !in MIN_TS..MAX_TS) {
            throw SecureCodeException("expires_at out of sane range")
        }
        if (issuedAt !in MIN_TS..MAX_TS) {
            throw SecureCodeException("issued_at out of sane range")
        }
        if (expiresAt != EXP_LIFETIME && expiresAt < issuedAt) {
            throw SecureCodeException("expires_at before issued_at")
        }
        if (!UUID_DASHED.matches(productId) && !UUID_PLAIN.matches(productId)) {
            throw SecureCodeException("product_id is not a UUID")
        }
        val compact = fingerprint.replace("-", "").trim().uppercase()
        if (compact.length != 16 || compact.any { it !in B32_ALPHABET }) {
            throw SecureCodeException("fingerprint field is not a valid machine code")
        }
        if (nonce.isNotEmpty()) {
            val lower = nonce.lowercase()
            if (lower.length != 32 || lower.any { it !in "0123456789abcdef" }) {
                throw SecureCodeException("nonce must be 16 bytes of hex")
            }
        }
    }
}
