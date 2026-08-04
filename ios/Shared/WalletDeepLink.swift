import Foundation

/// The set of quick actions a widget, Control Center control, or Siri shortcut can trigger. Each maps
/// to a screen the wallet already presents; none carries data.
public enum WalletDeepLink: String, CaseIterable, Sendable {
    case home
    case scan
    case present
    case passport
    case webEvidence = "web-evidence"
    case activity
    case catalogue
    case agents
    case settings

    /// Custom URL scheme the app registers (widgets use `widgetURL`; controls/intents use the
    /// pending-action store because a Control cannot carry a `widgetURL`).
    public static let scheme = "eu.advatar.wallet"

    public var url: URL {
        URL(string: "\(Self.scheme)://\(rawValue)")!
    }

    /// Parse a deep-link URL (`eu.advatar.wallet://present`). The action rides in the host, falling
    /// back to the first path component.
    public init?(url: URL) {
        guard url.scheme == Self.scheme else { return nil }
        let key = url.host?.isEmpty == false
            ? url.host!
            : url.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let link = WalletDeepLink(rawValue: key) else { return nil }
        self = link
    }
}

/// A one-shot pending action handed from a Control/Siri intent (which can only open the app) to the
/// app, consumed when the app next becomes active. Lives in the shared App Group.
public enum WalletPendingAction {
    private static let key = "wallet.pendingDeepLink"
    private static var defaults: UserDefaults? { UserDefaults(suiteName: WalletStatusStore.appGroup) }

    public static func set(_ link: WalletDeepLink) {
        defaults?.set(link.rawValue, forKey: key)
    }

    /// Return and clear the pending action, if any.
    public static func take() -> WalletDeepLink? {
        guard let raw = defaults?.string(forKey: key) else { return nil }
        defaults?.removeObject(forKey: key)
        return WalletDeepLink(rawValue: raw)
    }
}
