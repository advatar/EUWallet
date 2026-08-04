import Foundation
import WidgetKit

/// Privacy-safe status shared from the app to its widgets/controls via an App Group.
///
/// Widgets, Lock Screen accessories, and Control Center are visible to anyone holding the phone, so
/// only NON-sensitive status crosses this boundary — a document count, never credential contents or
/// any PII. The app writes on every holdings change and asks WidgetKit to reload.
public enum WalletStatusStore {
    /// Shared App Group container id (must be registered for the app + the widget extension).
    public static let appGroup = "group.eu.advatar.wallet"
    private static let documentCountKey = "wallet.documentCount"

    private static var defaults: UserDefaults? { UserDefaults(suiteName: appGroup) }

    /// Called by the app whenever the held-credential set changes.
    public static func publish(documentCount: Int) {
        defaults?.set(documentCount, forKey: documentCountKey)
        WidgetCenter.shared.reloadAllTimelines()
    }

    /// Read by the widget/control timeline provider. Defaults to 0 when unset.
    public static func documentCount() -> Int {
        defaults?.integer(forKey: documentCountKey) ?? 0
    }
}
