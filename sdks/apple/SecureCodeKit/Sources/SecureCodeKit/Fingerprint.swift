import Foundation
#if canImport(UIKit)
import UIKit
#endif
#if canImport(IOKit)
import IOKit
#endif
import Darwin

/// Device fingerprinting — the iOS/macOS port of
/// target_demo/protection/fingerprint.py. The four hash slots are filled
/// with platform-appropriate identifiers (names are stable hash labels):
///
///     macOS:
///       cpu   : built-in en0 MAC address (hardware, stable)
///       board : IOPlatformSerialNumber (the Mac serial, strongest)
///       guid  : IOPlatformUUID (hardware installation UUID)
///       disk  : reserved (empty)
///
///     iOS:
///       cpu   : Keychain UUID — SURVIVES uninstall/reinstall (Keychain
///               persists), resets only on full device erase
///       board : IDFV (identifierForVendor — changes only when ALL of the
///               vendor's apps are removed)
///       disk/guid: reserved (empty)
///
/// With tolerance=1, an IDFV change or a fresh Keychain entry after device
/// restore is still accepted; a machine code is NEVER stable across two
/// different physical devices.
enum Fingerprint {

    static let codeGroupSize = 4

    // ------------------------------------------------------------ collection
    static func collectComponents(_ config: ProtectionConfig) -> [String: String] {
        #if os(macOS)
        let cpu = en0Mac()
        let board = platformProperty("IOPlatformSerialNumber") ?? ""
        let disk = ""
        let guid = platformProperty("IOPlatformUUID") ?? ""
        #elseif os(iOS)
        let cpu = KeychainStore.ensureUUID(
            service: "com.securecode.device", account: config.productId) ?? ""
        let board = (UIDevice.current.identifierForVendor?.uuidString.lowercased() ?? "")
        let disk = ""
        let guid = ""
        #else
        let cpu = "", board = "", disk = "", guid = ""
        #endif
        return ["cpu": cpu, "board": board, "disk": disk, "guid": guid]
    }

    #if os(macOS)
    /// Serial / UUID from IOPlatformExpertDevice (macOS — no root needed).
    private static func platformProperty(_ name: String) -> String? {
        let matching = IOServiceMatching("IOPlatformExpertDevice")
        let port: io_service_t
        if #available(macOS 12.0, *) {
            port = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        } else {
            port = IOServiceGetMatchingService(kIOMasterPortDefault, matching)
        }
        guard port != 0 else { return nil }
        defer { IOObjectRelease(port) }
        var value: CFTypeRef?
        guard IORegistryEntryCreateCFProperty(
                port, name as CFString, &value, kCFAllocatorDefault) == KERN_SUCCESS,
              let string = value as? String
        else { return nil }
        return string
    }

    /// Built-in ethernet (en0) hardware MAC via getifaddrs (BSD).
    private static func en0Mac() -> String {
        var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddrPtr) == 0, let first = ifaddrPtr else { return "" }
        defer { freeifaddrs(ifaddrPtr) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            guard let ifaNameC = current.pointee.ifa_name else { continue }
            let name = String(cString: ifaNameC)
            guard name == "en0",
                  let saPtr = current.pointee.ifa_addr else { continue }
            let sa = saPtr.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { $0 }
            let alen = Int(sa.pointee.sdl_alen)
            let nlen = Int(sa.pointee.sdl_nlen)
            guard alen == 6, nlen > 0 else { continue }
            // sockaddr_dl header is 8 bytes; sdl_data[] follows, interface
            // name first (nlen bytes), then the link address (alen bytes).
            let macPtr = UnsafeMutableRawPointer(sa)
                .advanced(by: 8 + nlen)
                .assumingMemoryBound(to: UInt8.self)
            return (0..<6).map { String(format: "%02x", Int(macPtr[$0])) }
                .joined(separator: ":")
        }
        return ""
    }
    #endif

    // ------------------------------------------------------------ public API
    /// This device's machine code "XXXX-XXXX-XXXX-XXXX".
    static func machineCode(_ config: ProtectionConfig) -> String {
        let (_, material) = FingerprintDigest.compute(collectComponents(config))
        return FingerprintDigest.materialCode(material)
    }

    /// Bitmask of currently-present components.
    static func machineMask(_ config: ProtectionConfig) -> Int {
        FingerprintDigest.compute(collectComponents(config)).mask
    }

    /// Fingerprint matching WITH hardware-change tolerance (drop-combination
    /// search — mirrors the Windows client's matches()).
    static func matches(_ config: ProtectionConfig, targetCode: String,
                        tolerance: Int) -> Bool {
        let target = SCBase32.flatten(targetCode)
        let ours = collectComponents(config)
        let present = FingerprintDigest.componentOrder.filter {
            !(ours[$0] ?? "").isEmpty
        }

        func codeWithDrop(_ drop: Set<String>) -> String {
            var subset = ours
            for name in FingerprintDigest.componentOrder where drop.contains(name) {
                subset[name] = ""
            }
            return SCBase32.encode(FingerprintDigest.compute(subset).material)
        }

        if codeWithDrop([]) == target { return true }
        let maxK = min(tolerance, present.count)
        for k in 1...maxK {
            for drop in combinations(present, k) {
                if codeWithDrop(Set(drop)) == target { return true }
            }
        }
        return false
    }

    private static func combinations<T>(_ items: [T], _ k: Int) -> [[T]] {
        if k == 0 { return [[]] }
        if items.count < k { return [] }
        guard let head = items.first else { return [] }
        let tail = Array(items.dropFirst())
        return combinations(tail, k - 1).map { [head] + $0 } + combinations(tail, k)
    }

    /// Fingerprint export file the customer sends the vendor (JSON, no raw
    /// hardware identifiers).
    static func exportFingerprintFile(_ config: ProtectionConfig,
                                       to url: URL) throws -> URL {
        let platform: String
        #if os(macOS)
        platform = "macos"
        #elseif os(iOS)
        platform = "ios"
        #else
        platform = "unknown"
        #endif
        let payload: [String: Any] = [
            "format": SecureStrings.s("fp_export_format"),
            "version": 1,
            "platform": platform,
            "code": machineCode(config),
            "present": FingerprintDigest.parseComponentMask(machineMask(config)),
            "product_id": config.productId,
            "created": Int(Date().timeIntervalSince1970),
        ]
        try WireJson.prettyPrint(payload).write(to: url, atomically: true,
                                                 encoding: .utf8)
        return url
    }
}
