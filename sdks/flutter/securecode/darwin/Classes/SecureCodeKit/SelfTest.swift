import Foundation

/// Cross-platform conformance self-test — consumes sdks/vectors.json (the
/// SAME fixed vectors every platform SDK ships) and proves byte-exact wire
/// compatibility: Base32 codec, canonical JSON, fingerprint digests, full
/// serial verification (with the demo public key), Ed25519 (valid +
/// tampered) and HKDF machine-key derivation.
///
/// Run with:    swift test   (from sdks/apple/SecureCodeKit)
/// Validate a report with:
///     python -m tests.cross_platform_vectors --check <report.json>
public enum SecureCodeSelfTest {

    public struct Entry {
        public let name: String
        public let ok: Bool
        public let detail: String
    }

    public struct Report {
        public let allOk: Bool
        public let results: [Entry]
    }

    /// Run all vector checks against the JSON text of sdks/vectors.json.
    public static func run(_ vectorsJson: String) -> Report {
        guard let vectors = try? WireJson.parseObject(vectorsJson) else {
            return Report(allOk: false,
                          results: [Entry(name: "parse-vectors", ok: false, detail: "invalid JSON")])
        }
        var results: [Entry] = []

        func check(_ name: String, _ ok: Bool, _ detail: String = "") {
            results.append(Entry(name: name, ok: ok, detail: detail))
        }
        func hex(_ b: [UInt8]) -> String { CryptoUtils.toHex(b) }
        func dict(_ v: Any?) -> [String: Any] { (v as? [String: Any]) ?? [:] }
        func list(_ v: Any?) -> [Any] { (v as? [Any]) ?? [] }
        func string(_ v: Any?) -> String { (v as? String) ?? "" }
        func int64(_ v: Any?) -> Int64 { (v as? NSNumber)?.int64Value ?? 0 }
        func bool(_ v: Any?) -> Bool { (v as? Bool) ?? ((v as? NSNumber)?.boolValue ?? false) }

        // ---------------------------------------------------------- base32
        let base32Cases = list(vectors["base32"])
        for (i, caseAny) in base32Cases.enumerated() {
            let c = dict(caseAny)
            let data = CryptoUtils.fromHex(string(c["hex"]))
            let text = string(c["text"])
            let encoded = SCBase32.encode(data)
            check("base32[\(i)].encode", encoded == text, "got \(encoded)")
            let decoded = (try? SCBase32.decode(text)) ?? []
            check("base32[\(i)].decode", decoded == data)
            let repaired = c["repaired"].flatMap(string)
            if repaired != "" {
                let repairedDecoded = (try? SCBase32.decode(repaired)) ?? []
                check("base32[\(i)].repair", repairedDecoded == data)
            }
        }

        // ---------------------------------------------------- fingerprint
        for (i, caseAny) in list(vectors["fingerprint"]).enumerated() {
            let c = dict(caseAny)
            var raw: [String: String] = [:]
            for (k, v) in dict(c["components"]) {
                raw[k] = string(v)
            }
            let computed = FingerprintDigest.compute(raw)
            check("fingerprint[\(i)].mask",
                  computed.mask == Int(int64(c["mask"])),
                  "got \(computed.mask)")
            check("fingerprint[\(i)].material",
                  hex(computed.material) == string(c["material_hex"]),
                  "got \(hex(computed.material))")
            check("fingerprint[\(i)].code",
                  FingerprintDigest.materialCode(computed.material) == string(c["code"]),
                  "got \(FingerprintDigest.materialCode(computed.material))")
        }

        // -------------------------------------------------- canonical JSON
        for (i, caseAny) in list(vectors["canonical_json"]).enumerated() {
            let c = dict(caseAny)
            let expected = string(c["canonical_hex"])
            let got: String
            do {
                got = hex(try WireJson.canonicalBytes(c["payload"]))
            } catch {
                got = "error: \(error)"
            }
            check("canonical_json[\(i)]", got == expected, "got \(got)")
        }

        // -------------------------------------------------------- serials
        for (i, caseAny) in list(vectors["serial"]).enumerated() {
            let c = dict(caseAny)
            let serialText = string(c["serial"])
            let key = CryptoUtils.fromHex(string(c["public_key_hex"]))
            var payload: LicensePayload?
            var parseError = ""
            do {
                let (body, signature) = try Envelope.decode(serialText)
                let data = try WireJson.parseObject(String(decoding: body, as: UTF8.self))
                let p = try LicensePayload.fromWire(data)
                guard Ed25519.verify(publicKey: key, message: body, signature: signature)
                else { throw SignatureError() }
                payload = p
            } catch {
                parseError = "\(error)"
            }
            guard let p = payload else {
                check("serial[\(i)].verifies", false, parseError)
                continue
            }
            check("serial[\(i)].verifies", true)
            let expectedPayload = dict(c["payload"])
            check("serial[\(i)].product",
                  p.productId == string(expectedPayload["pid"]))
            check("serial[\(i)].expires",
                  p.expiresAt == int64(expectedPayload["exp"]))
            // Tamper: flip a char -> must fail verification.
            let flat = SCBase32.flatten(serialText)
            let badChar: Character = flat.last == "A" ? "B" : "A"
            let tampered = String(flat.dropLast()) + String(badChar)
            var tamperedAccepted = false
            if let (body, signature) = try? Envelope.decode(tampered),
               let data = try? WireJson.parseObject(String(decoding: body, as: UTF8.self)),
               (try? LicensePayload.fromWire(data)) != nil,
               Ed25519.verify(publicKey: key, message: body, signature: signature) {
                tamperedAccepted = true
            }
            check("serial[\(i)].tamper-rejected", !tamperedAccepted)
        }

        // ---------------------------------------------------------- ed25519
        for (i, caseAny) in list(vectors["ed25519"]).enumerated() {
            let c = dict(caseAny)
            let valid = Ed25519.verify(
                publicKey: CryptoUtils.fromHex(string(c["public_key_hex"])),
                message: CryptoUtils.fromHex(string(c["message_hex"])),
                signature: CryptoUtils.fromHex(string(c["signature_hex"])))
            check("ed25519[\(i)]", valid == bool(c["valid"]),
                  "got \(valid), expected \(bool(c["valid"]))")
        }

        // ------------------------------------------------------------ hkdf
        for (i, caseAny) in list(vectors["hkdf"]).enumerated() {
            let c = dict(caseAny)
            let key = CryptoUtils.deriveMachineKey(
                master: Array(string(c["master"]).data(using: .ascii) ?? Data()),
                machineCode: string(c["machine_code"]),
                productId: string(c["product_id"]),
                context: string(c["context"]))
            check("hkdf[\(i)]", hex(key) == string(c["key_hex"]), "got \(hex(key))")
        }

        return Report(allOk: results.allSatisfy { $0.ok }, results: results)
    }

    /// Report as the JSON text consumed by --check.
    public static func toJson(_ report: Report) -> String {
        let body: [String: Any] = [
            "sdk": "swift",
            "all_ok": report.allOk,
            "results": report.results.map { [
                "name": $0.name, "ok": $0.ok, "detail": $0.detail,
            ] as [String: Any] },
        ]
        return (try? WireJson.prettyPrint(body)) ?? "{}"
    }
}
