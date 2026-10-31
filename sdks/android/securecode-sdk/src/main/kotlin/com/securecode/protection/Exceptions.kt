package com.securecode.protection

/**
 * Exceptions mirroring shared/exceptions.py (both carry user-presentable
 * messages; the client never leaks which internal check failed beyond the
 * workflow's needs).
 */

/** Malformed serial / envelope / payload structure. */
open class SecureCodeException(message: String) : RuntimeException(message)

/** Valid structure, but the Ed25519 signature does not verify. */
class SignatureException(message: String = "signature mismatch") :
    SecureCodeException(message)

/** License state machine states surfaced by [LicenseClient]. */
enum class LicenseState {
    VALID,
    MISSING,          // never activated on this device
    INVALID,          // signature / structure failure
    EXPIRED,
    WRONG_MACHINE,    // serial bound to a different fingerprint
    REVOKED,          // nonce is on the signed blacklist
    CLOCK_TAMPERED,   // rollback beyond allowance
    DAMAGED,          // unreadable local store
    DEGRADED,         // silent anti-RE degrade mode active
}
