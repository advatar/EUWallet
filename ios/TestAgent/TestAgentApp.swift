import SwiftUI

/// A test harness (not a real wallet) for delegated-agent authority: an on-device model proposes an
/// action, and the shipped wallet-core delegation/agent engine decides whether the agent may do it.
@main
struct TestAgentApp: App {
    @StateObject private var model = TestAgentModel()

    var body: some Scene {
        WindowGroup { TestAgentView(model: model) }
    }
}
