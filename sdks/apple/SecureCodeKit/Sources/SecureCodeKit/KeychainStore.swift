import Foundation
import Security

/// Minimal Keychain wrapper (no dependencies): the iOS fingerprint's
/// stable-install UUID lives here because Keychain entries SURVIVE app
/// uninstall/reinstall (unlike UserDefaults/files) — the closest thing to
/// the Windows MachineGuid in durability.
enum KeychainStore {

    /// Read or create a UUID under [service/account]; returns nil on
    /// unavailable Keychain (rare: devices without Keychain entitlements).
    static func ensureUUID(service: String, account: String) -> String? {
        if let existing = read(service: service, account: account) {
            return existing
        }
        let fresh = UUID().uuidString.lowercased()
        let data = Data(fresh.utf8)
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecSuccess { return fresh }
        if status == errSecDuplicateItem { return read(service: service, account: account) }
        return nil
    }

    /// Store raw bytes (clock-guard watermark store).
    static func read(service: String, account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Store raw bytes (clock-guard watermark store).
    static func write(service: String, account: String, bytes: [UInt8]) -> Bool {
        let data = Data(bytes)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
        ]
        var update = query
        update[kSecValueData as String] = data
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return true }
        if status == errSecItemNotFound {
            return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
        }
        return false
    }

    static func delete(service: String, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
