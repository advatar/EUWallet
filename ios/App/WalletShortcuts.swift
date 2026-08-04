import AppIntents

/// Siri / Spotlight / Shortcuts phrases for the wallet's quick actions. Discovered automatically in
/// the app target; each phrase runs an intent that opens the app to the matching screen.
@available(iOS 16.0, *)
struct WalletShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: ScanIntent(),
            phrases: [
                "Scan with \(.applicationName)",
                "Open the \(.applicationName) scanner",
            ],
            shortTitle: "Scan a QR code",
            systemImageName: "qrcode.viewfinder")
        AppShortcut(
            intent: PresentIntent(),
            phrases: [
                "Show a document in \(.applicationName)",
                "Share a document with \(.applicationName)",
            ],
            shortTitle: "Show a document",
            systemImageName: "person.text.rectangle")
        AppShortcut(
            intent: AddFromPassportIntent(),
            phrases: [
                "Add a passport to \(.applicationName)",
            ],
            shortTitle: "Add from passport",
            systemImageName: "wave.3.right.circle")
        AppShortcut(
            intent: AddWebEvidenceIntent(),
            phrases: [
                "Add web evidence to \(.applicationName)",
            ],
            shortTitle: "Add web evidence",
            systemImageName: "checkmark.shield")
        AppShortcut(
            intent: OpenActivityIntent(),
            phrases: [
                "Show my \(.applicationName) activity",
            ],
            shortTitle: "Activity",
            systemImageName: "list.bullet.rectangle")
        AppShortcut(
            intent: ManageAgentsIntent(),
            phrases: [
                "Manage my \(.applicationName) agents",
            ],
            shortTitle: "My agents",
            systemImageName: "person.badge.key")
        AppShortcut(
            intent: OpenWalletIntent(),
            phrases: [
                "Open \(.applicationName)",
            ],
            shortTitle: "Open wallet",
            systemImageName: "wallet.pass")
    }
}
