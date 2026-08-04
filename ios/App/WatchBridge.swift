import Foundation
import WatchConnectivity

/// iPhone side of the watchOS companion bridge.
///
/// One-directional: mirrors the NON-sensitive document count to the paired Apple Watch glance. Only
/// the document COUNT ever crosses the WatchConnectivity link — never any credential contents, claim
/// values, or PII (the same status-only rule the widgets follow). The watch is a pure glance and
/// sends nothing back, so this side only pushes application context.
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
}
