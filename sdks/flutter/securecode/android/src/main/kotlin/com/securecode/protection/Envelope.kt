package com.securecode.protection

/**
 * The signed-envelope wire format shared by serial keys, blacklists and
 * transfer permits (mirrors shared/codec.py):
 *
 *     artifact_text = Base32( body_bytes || Ed25519_signature(64B) )
 *
 * Ed25519 signatures are fixed-length (RFC 8032), so no length prefix is
 * needed; the verifier splits the LAST 64 bytes.
 */
internal object Envelope {

    const val SIGNATURE_LEN = 64
    const val SERIAL_GROUP_SIZE = 5

    fun encode(body: ByteArray, signature: ByteArray): String {
        require(signature.size == SIGNATURE_LEN) {
            "Ed25519 signature must be $SIGNATURE_LEN bytes"
        }
        val raw = body + signature
        return Base32.groupBlocks(Base32.encode(raw), SERIAL_GROUP_SIZE)
    }

    /** Split artifact text into (body, signature).
     *  @throws SecureCodeException when too short / undecodable. */
    fun decode(text: String): Pair<ByteArray, ByteArray> {
        val raw = Base32.decode(text)
        if (raw.size < SIGNATURE_LEN) {
            throw SecureCodeException("serial is too short to contain a valid signature")
        }
        return Pair(raw.copyOfRange(0, raw.size - SIGNATURE_LEN),
                    raw.copyOfRange(raw.size - SIGNATURE_LEN, raw.size))
    }

    private operator fun ByteArray.plus(other: ByteArray): ByteArray {
        val out = ByteArray(size + other.size)
        System.arraycopy(this, 0, out, 0, size)
        System.arraycopy(other, 0, out, size, other.size)
        return out
    }
}
