#if canImport(SwiftUI)
import XCTest
@testable import WalletShell

/// App-shell routing tests (plan §8.10 Definition of Done). These assert the statechart's
/// transitions AND document its boundary: the navigation machine carries no security state.
@MainActor
final class NavigationTests: XCTestCase {
    func testOnboardingToHome() {
        let nav = NavigationMachine()
        XCTAssertEqual(nav.state, .onboarding)
        nav.send(.finishedOnboarding)
        XCTAssertEqual(nav.state, .home)
    }

    func testConsentRenderStartsPresentation() {
        let nav = NavigationMachine(state: .home)
        // The shell maps a `.consent` render to `.startPresentation` (a milestone, not protocol logic).
        nav.send(.startPresentation)
        XCTAssertEqual(nav.state, .presenting)
    }

    func testCredentialListRenderReturnsHome() {
        let nav = NavigationMachine(state: .presenting)
        // The shell maps a post-flow `.credentialList` render to `.presentationCompleted`.
        nav.send(.presentationCompleted)
        XCTAssertEqual(nav.state, .home)
    }

    func testDeepLinkPresentsFromAnyState() {
        for start: NavigationMachine.State in [.home, .settings, .scanning] {
            let nav = NavigationMachine(state: start)
            nav.send(.deepLinkArrived)
            XCTAssertEqual(nav.state, .presenting, "deep link should present from \(start)")
        }
    }

    func testOpenHistoryAndBack() {
        let nav = NavigationMachine(state: .home)
        nav.send(.openHistory)
        XCTAssertEqual(nav.state, .history)
        nav.send(.cancelled)
        XCTAssertEqual(nav.state, .home)
    }

    func testOpenCatalogueAndBack() {
        let nav = NavigationMachine(state: .home)
        nav.send(.openCatalogue)
        XCTAssertEqual(nav.state, .catalogue)
        nav.send(.cancelled)
        XCTAssertEqual(nav.state, .home)
    }

    func testCancelReturnsHome() {
        let nav = NavigationMachine(state: .presenting)
        nav.send(.cancelled)
        XCTAssertEqual(nav.state, .home)
    }

    func testIllegalTransitionsAreIgnored() {
        // Can't finish onboarding when already home; can't open settings mid-onboarding.
        let home = NavigationMachine(state: .home)
        home.send(.finishedOnboarding)
        XCTAssertEqual(home.state, .home)

        let onboarding = NavigationMachine(state: .onboarding)
        onboarding.send(.openSettings)
        XCTAssertEqual(onboarding.state, .onboarding)
    }

    // MARK: - Formal conformance (formal/lean/NavigationModel.lean)
    //
    // The Lean model proves the flow-safety properties of this statechart; these tests bind the
    // SHIPPED Swift machine to the exact same transition table + invariants, EXHAUSTIVELY over all
    // (state × event) pairs — the model↔code refinement the core uses (plan Section 10). If the
    // Swift `send` ever drifts from the proven model, one of these fails.

    /// Apply one event to a fresh machine in `state` and return the resulting state.
    private func after(_ state: NavigationMachine.State, _ event: NavigationMachine.Event)
        -> NavigationMachine.State
    {
        let nav = NavigationMachine(state: state)
        nav.send(event)
        return nav.state
    }

    /// The transition table, mirroring `NavigationModel.step` in Lean (event-first).
    private func expected(_ s: NavigationMachine.State, _ e: NavigationMachine.Event)
        -> NavigationMachine.State
    {
        switch e {
        case .deepLinkArrived, .startPresentation: return .presenting
        case .presentationCompleted, .cancelled: return .home
        case .finishedOnboarding: return s == .onboarding ? .home : s
        case .startIssuance: return s == .home ? .issuing : s
        case .openScanner: return s == .home ? .scanning : s
        case .openSettings: return s == .home ? .settings : s
        case .openHistory: return s == .home ? .history : s
        case .openCatalogue: return s == .home ? .catalogue : s
        }
    }

    /// Every one of the 8 × 10 (state, event) transitions matches the Lean-proven table.
    func testExhaustiveTransitionTableMatchesModel() {
        for s in NavigationMachine.State.allCases {
            for e in NavigationMachine.Event.allCases {
                XCTAssertEqual(after(s, e), expected(s, e), "transition (\(s), \(e)) diverged from the model")
            }
        }
    }

    /// The flow-safety invariants proved in `NavigationModel.lean`, checked on every state.
    func testProvenInvariantsHoldOnEveryState() {
        for s in NavigationMachine.State.allCases {
            // cancel_returns_home / complete_returns_home — the user is never trapped.
            XCTAssertEqual(after(s, .cancelled), .home)
            XCTAssertEqual(after(s, .presentationCompleted), .home)
            // deeplink_presents / consent_presents — flow entry from any state.
            XCTAssertEqual(after(s, .deepLinkArrived), .presenting)
            XCTAssertEqual(after(s, .startPresentation), .presenting)
            // home_reachable — home is reachable from every state in one event.
            XCTAssertTrue(NavigationMachine.Event.allCases.contains { after(s, $0) == .home })

            for e in NavigationMachine.Event.allCases {
                // onboarding_not_reentered — no event routes INTO onboarding from another state.
                if after(s, e) == .onboarding {
                    XCTAssertEqual(s, .onboarding, "event \(e) re-entered onboarding from \(s)")
                }
                // presenting_entered_only_via_flow_entry.
                if after(s, e) == .presenting {
                    XCTAssertTrue(
                        s == .presenting || e == .deepLinkArrived || e == .startPresentation,
                        "event \(e) entered presenting from \(s) outside a flow-entry milestone")
                }
            }
        }
    }
}
#endif
