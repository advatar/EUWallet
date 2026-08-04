import Foundation
import WatchConnectivity

/// watchOS side of the companion bridge.
///
/// Receives the NON-sensitive document count from the paired iPhone (over WatchConnectivity's
/// latest-wins application context) and publishes it to the glance. One-directional: the watch only
/// ever knows *how many* documents the wallet holds — no credential contents cross the link, and the
/// watch sends nothing back.
///
/// The last known count is cached in the watch's own `UserDefaults` so the glance is populated
/// instantly on launch, before the phone has a chance to push a fresh value.
final class WatchConnectivityClient: NSObject, ObservableObject {
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
