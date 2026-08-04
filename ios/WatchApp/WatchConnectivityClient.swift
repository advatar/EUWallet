import Foundation
import WatchConnectivity

/// watchOS side of the companion bridge.
///
/// Receives the NON-sensitive document count from the paired iPhone (over WatchConnectivity's
/// latest-wins application context) and sends coarse quick-action requests back. No credential
/// contents ever cross the link — the watch only ever knows *how many* documents the wallet holds.
///
/// The last known count is cached in the watch's own `UserDefaults` so the glance is populated
/// instantly on launch, before the phone has a chance to push a fresh value.
final class WatchConnectivityClient: NSObject, ObservableObject {
    /// Quick actions the watch can request. Raw values mirror the iPhone's `WalletDeepLink` cases so
    /// the phone routes them through its existing deep-link handler.
    enum Action: String {
        case scan
        case present
    }

    @Published private(set) var documentCount: Int
    @Published private(set) var reachable: Bool = false

    private static let countKey = "documentCount"

    override init() {
        documentCount = UserDefaults.standard.integer(forKey: Self.countKey)
        super.init()
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        session.delegate = self
        session.activate()
    }

    /// Ask the iPhone to perform a quick action. Uses `sendMessage` when the phone is reachable
    /// (delivered immediately) and falls back to a queued `transferUserInfo` otherwise. The watch
    /// cannot bring the iPhone app to the foreground — Apple reserves that — so a queued action is
    /// applied the next time the user opens the wallet on their phone.
    func request(_ action: Action) {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        let payload = ["action": action.rawValue]
        if session.isReachable {
            session.sendMessage(payload, replyHandler: nil) { _ in
                session.transferUserInfo(payload)
            }
        } else {
            session.transferUserInfo(payload)
        }
    }

    private func apply(_ context: [String: Any]) {
        guard let count = context[Self.countKey] as? Int else { return }
        UserDefaults.standard.set(count, forKey: Self.countKey)
        DispatchQueue.main.async { self.documentCount = count }
    }
}

extension WatchConnectivityClient: WCSessionDelegate {
    func session(
        _ session: WCSession,
        activationDidCompleteWith _: WCSessionActivationState,
        error _: Error?
    ) {
        let isReachable = session.isReachable
        let latest = session.receivedApplicationContext
        DispatchQueue.main.async { self.reachable = isReachable }
        apply(latest)
    }

    func session(_: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
        apply(applicationContext)
    }

    func sessionReachabilityDidChange(_ session: WCSession) {
        let isReachable = session.isReachable
        DispatchQueue.main.async { self.reachable = isReachable }
    }
}
