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
}
#endif
