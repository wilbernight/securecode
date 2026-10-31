// swift-tools-version:5.9
import PackageDescription

// SecureCodeKit — offline licensing client SDK for iOS 13+ and macOS 10.15+.
// Zero external dependencies: CryptoKit + Foundation + Security only.
// Byte-compatible with the SecureCode protector's wire format (proved by
// Tests/SecureCodeKitTests against sdks/vectors.json).
let package = Package(
    name: "SecureCodeKit",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        .library(name: "SecureCodeKit", targets: ["SecureCodeKit"]),
    ],
    targets: [
        .target(
            name: "SecureCodeKit",
            swiftSettings: [.unsafeFlags([])]),
        .testTarget(
            name: "SecureCodeKitTests",
            resources: [.copy("vectors.json")]),
    ]
)
