// swift-tools-version:5.9
// Shared-darwin-source SPM manifest (used when the app enables Flutter's
// Swift Package Manager support; classic CocoaPods builds use
// securecode.podspec — both compile the same Classes/ sources).
import PackageDescription

let package = Package(
    name: "securecode",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        .library(name: "securecode", targets: ["securecode"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "securecode",
            path: "Classes"),
    ]
)
