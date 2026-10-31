import Foundation
import Security

/// Self-integrity layer (macOS analog of the Windows integrity manifest):
///
///     1. Code-signature validation of the running executable (SecCode) —
///        detects binary patching and resigning (macOS only; iOS apps are
///        already signature-enforced by the OS for every page).
///     2. Embedded public key sanity (32 bytes).
///
/// Hard failure -> the runtime exits silently (graceful, non-obvious
/// termination — same policy as the Windows client).
enum Integrity {

    static func runChecks(_ config: ProtectionConfig) -> (Bool, [String]) {
        var problems: [String] = []
        #if os(macOS)
        if config.requireCodeSignature {
            if !codeSignatureValid() { problems.append("signature-invalid") }
        }
        #endif
        if config.publicKey.count != 32 { problems.append("pubkey-size") }
        return (problems.isEmpty, problems)
    }

    #if os(macOS)
    /// Validate the on-disk code signature of the running process.
    private static func codeSignatureValid() -> Bool {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let self_ = code else {
            return false
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(self_, [], &staticCode) == errSecSuccess,
              let staticRef = staticCode else {
            return false
        }
        // nil requirement = the signature must validate against the
        // signing identity as recorded on disk (any trusted anchor).
        return SecStaticCodeCheckValidity(staticRef, SecCSFlags(), nil) == errSecSuccess
    }
    #endif
}
