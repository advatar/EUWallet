import Foundation
import WatchConnectivity

extension Notification.Name {
    /// Posted (on the main queue) when the paired Apple Watch requests a quick action. The object is
    /// the `WalletDeepLink` to route through the app's existing `apply(_:)` handler.
    static let walletWatchAction = Notification.Name("eu.advatar.wallet.watchAction")
}

/// iPhone side of the watchOS companion bridge.
///
/// Mirrors the NON-sensitive document count to the paired Apple Watch and receives quick-action
/// requests from it. Only the document COUNT and coarse action identifiers cross the
/// WatchConnectivity link — never any credential contents, claim values, or PII (the same
/// status-only rule the widgets follow).
///
/// A watch action is stored as a `WalletPendingAction` (consumed when the app next becomes active)
/// AND posted as `.walletWatchAction` so an already-foreground app routes it immediately. The watch
/// cannot force the iPhone app to the foreground — that is an Apple platform restriction — so an
/// action requested while the phone app is closed is applied the next time the user opens it.
final class WatchBridge: NSObject, WCSessionDelegate {
    static let shared = WatchBridge()

    /// A count published before the session finished activating; flushed on activation.
    private var pendingCount: Int?

    /// Activate the shared session (safe no-op on devices without a paired watch).
    func activate() {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        session.delegate = self
        session.activate()
    }

    /// Push the current document count to the watch (latest-wins application context).
    func sync(documentCount: Int) {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        guard session.activationState == .activated else {
            pendingCount = documentCount
            return
        }
        try? session.updateApplicationContext(["documentCount": documentCount])
    }

    // MARK: - WCSessionDelegate

    func session(
        _ session: WCSession,
        activationDidCompleteWith activationState: WCSessionActivationState,
        error _: Error?
    ) {
        if activationState == .activated, let count = pendingCount {
            pendingCount = nil
            sync(documentCount: count)
        }
    }

    // Required on iOS so the session can re-pair after switching watches.
    func sessionDidBecomeInactive(_: WCSession) {}
    func sessionDidDeactivate(_: WCSession) { WCSession.default.activate() }

    func session(_: WCSession, didReceiveMessage message: [String: Any]) {
        route(message)
    }

    func session(
        _: WCSession,
        didReceiveMessage message: [String: Any],
        replyHandler: @escaping ([String: Any]) -> Void
    ) {
        route(message)
        replyHandler(["ok": true])
    }

    func session(_: WCSession, didReceiveUserInfo userInfo: [String: Any] = [:]) {
        route(userInfo)
    }

    private func route(_ message: [String: Any]) {
        guard let raw = message["action"] as? String,
              let link = WalletDeepLink(rawValue: raw)
        else { return }
        WalletPendingAction.set(link)
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: .walletWatchAction, object: link)
        }
    }
}
