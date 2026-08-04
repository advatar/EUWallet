import ActivityKit
import Foundation

/// Drives the "Adding your document" Live Activity across the issuance lifecycle so `WalletModel`
/// can start/advance/finish it without touching ActivityKit directly.
///
/// Holds at most one in-flight activity (issuance is one OpenID4VCI session at a time). Every call
/// is a safe no-op when Live Activities are unavailable or the user has disabled them, so callers
/// never need to branch on availability. Terminal states linger briefly on the Lock Screen before
/// the system dismisses them.
@MainActor
final class LiveActivityController {
    static let shared = LiveActivityController()

    private var activity: Activity<WalletIssuanceAttributes>?

    private init() {}

    /// Begin a new issuance activity for `documentName`. Ends any stale activity first so a second
    /// issuance never stacks two Lock Screen cards.
    func start(documentName: String, systemImage: String) {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        dismiss()
        let attributes = WalletIssuanceAttributes(
            documentName: documentName, systemImage: systemImage)
        let initial = WalletIssuanceAttributes.ContentState(stage: .connecting)
        activity = try? Activity.request(
            attributes: attributes,
            content: .init(state: initial, staleDate: nil))
    }

    /// Move the current activity to a non-terminal stage (`connecting`/`reviewing`/`finishing`).
    func advance(to stage: WalletIssuanceAttributes.ContentState.Stage) {
        guard let activity else { return }
        let content = ActivityContent(
            state: WalletIssuanceAttributes.ContentState(stage: stage), staleDate: nil)
        Task { await activity.update(content) }
    }

    /// Move the current activity to a terminal stage (`done`/`failed`) and let the system dismiss it
    /// after a short dwell so the outcome is visible on the Lock Screen.
    func finish(_ stage: WalletIssuanceAttributes.ContentState.Stage) {
        guard let activity else { return }
        self.activity = nil
        let content = ActivityContent(
            state: WalletIssuanceAttributes.ContentState(stage: stage), staleDate: nil)
        Task {
            await activity.end(content, dismissalPolicy: .after(.now.addingTimeInterval(4)))
        }
    }

    /// Remove the current activity immediately (e.g. the holder declined the offer — no outcome to
    /// dwell on).
    func dismiss() {
        guard let activity else { return }
        self.activity = nil
        Task { await activity.end(nil, dismissalPolicy: .immediate) }
    }
}
