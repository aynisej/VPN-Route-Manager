// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "VPNRouteManager",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "VPNRouteManager", targets: ["VPNRouteManager"])
    ],
    targets: [
        .executableTarget(name: "VPNRouteManager", path: "Sources/VPNRouteManager")
    ]
)
