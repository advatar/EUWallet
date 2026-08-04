// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "TLSNotaryMobile",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "TLSNotaryMobile", targets: ["TLSNotaryMobile"]),
    ],
    targets: [
        .binaryTarget(
            name: "TLSNMobileFFI",
            path: "Artifacts/TLSNMobile.xcframework"
        ),
        .target(
            name: "TLSNotaryMobile",
            dependencies: ["TLSNMobileFFI"]
        ),
        // Vendored into EUWallet without the package's own tests (Tests/ not copied).
    ]
)
