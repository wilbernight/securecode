package com.securecode.protection

import java.math.BigInteger
import java.security.MessageDigest

/**
 * Pure-Kotlin RFC 8032 Ed25519 SIGNATURE VERIFICATION (deterministic, no
 * dependencies, works on every Android API level — java.security's Ed25519
 * only arrived on API 33).
 *
 * Verification-only on purpose: the private key never leaves the protector.
 * Scalar multiplication uses variable-time BigInteger arithmetic — there
 * are no secrets on this side of the protocol, so constant-time discipline
 * is not required here (unlike the signing side).
 *
 * Byte-compatible with OpenSSL / Python `cryptography` — proven against
 * the fixed conformance vectors in sdks/vectors.json.
 */
internal object Ed25519 {

    // Field and group parameters ------------------------------------------------
    private val P: BigInteger = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))
    private val L: BigInteger = BigInteger.TWO.pow(252)
        .add(BigInteger("27742317777372353535851937790883648493"))
    private val D: BigInteger = BigInteger.valueOf(-121665)
        .mod(P).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)
    private val SQRT_M1: BigInteger =
        BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).divide(BigInteger.valueOf(4)), P)
    private val MASK_LOW_255: BigInteger = BigInteger.TWO.pow(255).subtract(BigInteger.ONE)

    /** Base point (RFC 8032 §5.1) — well-known constants. */
    private val BX: BigInteger =
        BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202")
    private val BY: BigInteger =
        BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960")

    // ---------------------------------------------------------------- public API
    /** Verify an Ed25519 signature. Returns false for ANY malformed input
     *  (never throws) — a rejected signature must simply read as invalid. */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.size != 32 || signature.size != 64) return false
        val a = decodePoint(publicKey) ?: return false
        val r = decodePoint(signature.copyOfRange(0, 32)) ?: return false
        val s = leInt(signature, 32, 32) // S = signature bytes 32..63, little-endian
        if (s >= L) return false
        // RFC 8032: h = SHA-512(R || A || M) interpreted LITTLE-endian, mod L.
        val h = BigInteger(1, sha512(
            signature.copyOfRange(0, 32) + publicKey + message).reversedArray())
            .mod(L)
        // [S]B == R + [h]A
        val lhs = BASE.multiply(s)
        val rhs = r.add(a.multiply(h))
        return lhs.equalsProjective(rhs)
    }

    // ---------------------------------------------------------------- points
    /** Extended twisted-Edwards coordinates (x = X/Z, y = Y/Z, T = XY/Z). */
    private class Pt(X: BigInteger, Y: BigInteger, Z: BigInteger, T: BigInteger) {
        val x = X.mod(P); val y = Y.mod(P); val z = Z.mod(P); val t = T.mod(P)
        constructor(X: BigInteger, Y: BigInteger) : this(X, Y, BigInteger.ONE, X.multiply(Y).mod(P))

        /** add-2008-hwcd-3 (unified, a = -1). */
        operator fun plus(other: Pt): Pt {
            val a = (y - x).multiply(other.y - other.x)
            val b = (y + x).multiply(other.y + other.x)
            val c = t.multiply(D).multiply(other.t).shiftLeft(1)
            val d = z.multiply(other.z).shiftLeft(1)
            val e = b - a; val f = d - c; val g = d + c; val h = b + a
            return Pt(e.multiply(f), g.multiply(h), f.multiply(g), e.multiply(h))
        }

        /** dbl-2008-hwcd (a = -1). */
        fun double(): Pt {
            val a = x.multiply(x)
            val b = y.multiply(y)
            val c = z.multiply(z).shiftLeft(1)
            val h = a + b
            val e = h - (x + y).multiply(x + y)
            val g = a - b
            val f = c + g
            return Pt(e.multiply(f), g.multiply(h), f.multiply(g), e.multiply(h))
        }

        fun multiply(scalar: BigInteger): Pt {
            var result = IDENTITY
            var addend = this
            var k = scalar
            while (k.signum() > 0) {
                if (k.testBit(0)) result = result + addend
                addend = addend.double()
                k = k.shiftRight(1)
            }
            return result
        }

        fun equalsProjective(other: Pt): Boolean =
            (x.multiply(other.z) - other.x.multiply(z)).mod(P).signum() == 0 &&
                    (y.multiply(other.z) - other.y.multiply(z)).mod(P).signum() == 0
    }

    private val IDENTITY = Pt(BigInteger.ZERO, BigInteger.ONE)
    private val BASE = Pt(BX, BY)

    // ---------------------------------------------------------------- decoding
    /** RFC 8032 §5.1.3 point decompression; null when the encoding is
     *  invalid (off-curve / non-square / non-canonical). */
    private fun decodePoint(data: ByteArray): Pt? {
        val sign = (data[31].toInt() shr 7) and 1
        val y = leInt(data, 0, 32).and(MASK_LOW_255) // clears the sign bit
        if (y >= P) return null
        val x = recoverX(y, sign) ?: return null
        return Pt(x, y)
    }

    private fun recoverX(y: BigInteger, sign: Int): BigInteger? {
        val y2 = y.multiply(y).mod(P)
        val u = y2.subtract(BigInteger.ONE).mod(P)
        val v = D.multiply(y2).add(BigInteger.ONE).mod(P)
        var x = u.multiply(v.modPow(BigInteger.valueOf(3), P))
            .multiply(u.multiply(v.modPow(BigInteger.valueOf(7), P))
                .modPow(P.subtract(BigInteger.valueOf(5))
                    .divide(BigInteger.valueOf(8)), P)).mod(P)
        when {
            (v.multiply(x).multiply(x).subtract(u)).mod(P).signum() == 0 -> { /* x ok */ }
            (v.multiply(x).multiply(x).add(u)).mod(P).signum() == 0 ->
                x = x.multiply(SQRT_M1).mod(P)
            else -> return null // not a square -> not on curve
        }
        if (x.signum() == 0 && sign == 1) return null
        if (x.testBit(0) != (sign == 1)) x = P - x
        return x
    }

    // ---------------------------------------------------------------- helpers
    /** Interpret data[offset .. offset+len-1] as a little-endian unsigned int. */
    private fun leInt(data: ByteArray, offset: Int, len: Int): BigInteger {
        val reversed = ByteArray(len)
        for (i in 0 until len) reversed[i] = data[offset + len - 1 - i]
        return BigInteger(1, reversed)
    }

    private fun sha512(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-512").digest(data)

    private operator fun ByteArray.plus(other: ByteArray): ByteArray {
        val out = ByteArray(size + other.size)
        System.arraycopy(this, 0, out, 0, size)
        System.arraycopy(other, 0, out, size, other.size)
        return out
    }
}
