// swift-tools-version: 6.0
import PackageDescription

// iOS shell for the EUDI wallet. The behaviour core is Rust (see ../crates), exposed via
// UniFFI (see docs/IMPLEMENTATION_PLAN.md Section 3). This package holds the thin native
// shell: renderer, effect executor, hardware signer, transports, storage.
//
// For the skeleton the core is represented by hand-written mirror types in `CoreBridge.swift`;
// Section 3 replaces these with the UniFFI-generated bindings.
let package = Package(
    name: "WalletShell",
    platforms: [.iOS(.v17), .macOS(.v13)],
    products: [
        .library(name: "WalletShell", targets: ["WalletShell"])
    ],
    targets: [
        .target(name: "WalletShell"),
        .testTarget(name: "WalletShellTests", dependencies: ["WalletShell"]),
    ]
)
