import XCTest
@testable import SecureCodeKit

/// Cross-platform conformance suite — proves byte-exact compatibility with
/// the protector's wire format (sdks/vectors.json).
///
/// Run:    cd sdks/apple/SecureCodeKit && swift test
/// Report: the run writes securecode-selftest.json next to the test
///         products dir — validate with
///         python -m tests.cross_platform_vectors --check <report>
final class VectorConformanceTests: XCTestCase {

    private func vectorsJson() throws -> String {
        let bundle = Bundle(for: VectorConformanceTests.self)
        guard let url = bundle.url(forResource: "vectors", withExtension: "json") else {
            throw XCTSkip("vectors.json resource missing — run from the repo checkout")
        }
        return try String(contentsOf: url, encoding: .utf8)
    }

    func testVectorConformance() throws {
        let report = SecureCodeSelfTest.run(try vectorsJson())
        report.results.filter { !$0.ok }
            .forEach { XCTFail("vector '\($0.name)' failed: \($0.detail)") }
        XCTAssertFalse(report.results.isEmpty, "no vectors ran")
        print("securecode swift sdk: \(report.results.count) vectors passed")

        // Machine-readable report for tests/cross_platform_vectors --check
        let out = URL(fileURLWithPath: "securecode-selftest.json")
        try? SecureCodeSelfTest.toJson(report)
            .write(to: out, atomically: true, encoding: .utf8)
    }

    // -------------------------------------------------- targeted checks
    func testCanonicalJsonMatchesPythonExactly() throws {
        let bytes = try WireJson.canonicalBytes(["cust": "شرکت", "v": 1])
        XCTAssertEqual(
            String(decoding: bytes, as: UTF8.self),
            "{\"cust\":\"\\u0634\\u0631\\u06a9\\u062a\",\"v\":1}")
    }

    func testSurrogatePairsEscapeLikePython() throws {
        let bytes = try WireJson.canonicalBytes(["k": "😀"])
        XCTAssertEqual(String(decoding: bytes, as: UTF8.self),
                       "{\"k\":\"\\ud83d\\ude00\"}")
    }

    func testBase32RoundTrip() throws {
        for n in [0, 1, 2, 5, 10, 31, 64] {
            let data = (0..<n).map { UInt8(($0 * 37) % 251) }
            let text = SCBase32.encode(data)
            XCTAssertFalse(text.contains("="))
            XCTAssertTrue(text.allSatisfy { "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains($0) })
            XCTAssertEqual(try SCBase32.decode(text), data, "round trip \(n)")
        }
    }

    func testFingerprintToleranceDropsComponents() {
        let full = ["cpu": "CPUID-1", "board": "BOARD-1",
                    "disk": "DISK-1", "guid": "GUID-1"]
        let code = FingerprintDigest.materialCode(FingerprintDigest.compute(full).material)
        var dropped = full
        dropped["guid"] = ""
        let droppedCode = FingerprintDigest.materialCode(
            FingerprintDigest.compute(dropped).material)
        XCTAssertNotEqual(code, droppedCode)
        for c in [code, droppedCode] {
            XCTAssertEqual(c.count, 19)
            XCTAssertEqual(c.filter { $0 == "-" }.count, 3)
        }
    }

    func testPackU64BigEndian() {
        let v: UInt64 = 0x0123456789ABCDEF
        XCTAssertEqual(CryptoUtils.toHex(CryptoUtils.packU64(v)), "0123456789abcdef")
        XCTAssertEqual(CryptoUtils.unpackU64(CryptoUtils.packU64(v)), v)
    }

    func testHkdfMatchesRfcVector() {
        // RFC 5869 Test Case 1 (SHA-256)
        let ikm = [UInt8](repeating: 0x0b, count: 22)
        let salt = CryptoUtils.fromHex("000102030405060708090a0b0c")
        let info = CryptoUtils.fromHex("f0f1f2f3f4f5f6f7f8f9")
        let okm = CryptoUtils.hkdfSHA256(ikm: ikm, salt: salt, info: info, length: 42)
        XCTAssertEqual(
            CryptoUtils.toHex(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865")
    }

    func testGcmRoundTripAndTamper() throws {
        let key = (0..<32).map { UInt8($0) }
        let pt = Array("machine-bound payload".utf8)
        let ct = try CryptoUtils.gcmEncrypt(key: key, plaintext: pt)
        XCTAssertEqual(ct.count, pt.count + 12 + 16)
        XCTAssertEqual(try CryptoUtils.gcmDecrypt(key: key, blob: ct), pt)
        var tampered = ct
        tampered[tampered.count - 1] ^= 1
        XCTAssertThrowsError(try CryptoUtils.gcmDecrypt(key: key, blob: tampered))
    }

    func testPayloadValidationRejectsGarbage() {
        let good: [String: Any] = ["v": 1, "fp": "AB234567CDEFGHIJ",
                                   "pid": "7e9a6cec-c185-45bb-a2fb-d31e96484f7e",
                                   "iat": 1_770_000_000, "exp": 1_803_542_400]
        XCTAssertNoThrow(try LicensePayload.fromWire(good))
        for bad in [
            ["v": 2, "fp": "AB234567CDEFGHIJ",
             "pid": "7e9a6cec-c185-45bb-a2fb-d31e96484f7e",
             "iat": 1_770_000_000, "exp": 1_803_542_400],
            ["v": 1, "fp": "NOT-A-CODE",
             "pid": "7e9a6cec-c185-45bb-a2fb-d31e96484f7e",
             "iat": 1_770_000_000, "exp": 1_803_542_400],
            ["v": 1, "fp": "AB234567CDEFGHIJ", "pid": "not-a-uuid",
             "iat": 1_770_000_000, "exp": 1_803_542_400],
            ["v": 1, "fp": "AB234567CDEFGHIJ",
             "pid": "7e9a6cec-c185-45bb-a2fb-d31e96484f7e",
             "iat": 1_770_000_000, "exp": 9_999_999_999],
        ] {
            XCTAssertThrowsError(try LicensePayload.fromWire(bad), "must reject \(bad)")
        }
    }
}
