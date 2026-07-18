#if canImport(SwiftUI)
import SwiftUI

/// App-shell navigation statechart (plan §8.10). This is **strictly outside the certification
/// core**: it decides screen *containment/routing* (onboarding vs. home vs. the modal that hosts a
/// flow vs. settings), while the Rust core decides screen *content* (`ScreenDescription`). The two
/// are orthogonal — the `ScreenRenderer` draws whatever the core emits inside whatever container
/// this machine currently presents.
///
/// Boundary rules (enforced in review, see `NavigationTests`):
///  1. It never validates anything, never touches crypto or storage, and never inspects credential
///     data. It reacts only to coarse **milestone events** the shell derives from what the core
///     rendered (e.g. a consent render ⇒ `.startPresentation`; the flow ending ⇒ `.presentationCompleted`).
///  2. It holds no security state.
///  3. It runs on the main actor.
@MainActor
public final class NavigationMachine: ObservableObject {
    public enum State: Equatable {
        case onboarding, home, presenting, issuing, scanning, settings, history
    }

    public enum Event {
        case finishedOnboarding
        case startPresentation
        case startIssuance
        case openScanner
        case openSettings
        case openHistory
        case presentationCompleted
        case cancelled
        case deepLinkArrived
    }

    @Published public private(set) var state: State

    public init(state: State = .onboarding) {
        self.state = state
    }

    /// Apply a milestone event. Illegal transitions are ignored (the machine simply stays put),
    /// so the shell can fire events optimistically without guarding each call site.
    public func send(_ event: Event) {
        switch (state, event) {
        case (.onboarding, .finishedOnboarding):
            state = .home
        // A request can arrive at any time (deep link, or a consent screen the core just produced)
        // → present the flow. This is the only "from any state" transition.
        case (_, .deepLinkArrived), (_, .startPresentation):
            state = .presenting
        case (.home, .startIssuance):
            state = .issuing
        case (.home, .openScanner):
            state = .scanning
        case (.home, .openSettings):
            state = .settings
        case (.home, .openHistory):
            state = .history
        // A flow always returns to home when it finishes or is cancelled, wherever we were.
        case (_, .presentationCompleted), (_, .cancelled):
            state = .home
        default:
            break  // ignore illegal transitions
        }
    }
}
#endif
