import SwiftUI

/// EU Wallet's watchOS companion. A thin, privacy-safe glance + quick-action surface that mirrors the
/// document count from the paired iPhone and nudges it to scan or share. It holds no credentials and
/// runs no wallet-core logic — all security-bearing flows stay on the phone.
@main
struct EUWalletWatchApp: App {
    var body: some Scene {
        WindowGroup {
            WatchRootView()
        }
    }
}
