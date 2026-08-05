import Foundation

/// Drives the TestAgent: an on-device model proposes the powers a goal needs, then the wallet
/// (`exerciseMandate`, wallet-core) decides whether the agent may exercise them and returns a
/// verifiable receipt. Model and authority are deliberately separate objects.
@MainActor
final class TestAgentModel: ObservableObject {
    @Published var goal = "Prove I'm over 18"
    @Published var proposed: [String] = []  // power URNs the model proposed
    @Published var planning = false
    @Published var humanApproved = false
    @Published var result: AgentResult?

    /// What this agent was delegated — its mandate. Grants most powers but NOT `administer-account`,
    /// so an admin goal demonstrates a refusal-at-selection (the wallet cannot over-claim).
    let mandate: [String] = [
        "urn:eudi:mandate:power:present-identity",
        "urn:eudi:mandate:power:sign-document",
        "urn:eudi:mandate:power:access-records",
        "urn:eudi:mandate:power:manage-subscription",
        "urn:eudi:mandate:power:authorise-payment",
    ]

    let plannerName: String
    private let planner: AgentPlanner

    init() {
        let planner = makePlanner()
        self.planner = planner
        self.plannerName = planner.name
    }

    /// Model step: propose the powers the goal needs (no authority involved).
    func plan() async {
        planning = true
        result = nil
        proposed = await planner.propose(goal: goal)
        planning = false
    }

    /// Authority step: the wallet decides and (maybe) signs, returning a receipt.
    func exercise() {
        let json = exerciseMandate(
            mandatePowers: mandate, requestedPowers: proposed, humanApproved: humanApproved)
        result = AgentResult(json: json)
    }
}

/// Decoded view of the JSON `exerciseMandate` returns.
struct AgentResult {
    let decision: String  // "signed" | "refused" | "error"
    let stage: String?  // "selection" | "signing"
    let requiredTier: String?
    let steppedUp: Bool
    let heldForApproval: Bool
    let onBehalfOf: String?
    let mandateJti: String?
    let receiptSeq: Int?
    let exercisedScope: [String]
    let withinGrant: Bool
    let receiptChainVerified: Bool
    let reason: String?

    init(json: String) {
        let obj = ((try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any]) ?? [:]
        decision = obj["decision"] as? String ?? "error"
        stage = obj["stage"] as? String
        requiredTier = obj["requiredTier"] as? String
        steppedUp = obj["steppedUp"] as? Bool ?? false
        heldForApproval = obj["heldForApproval"] as? Bool ?? false
        onBehalfOf = obj["onBehalfOf"] as? String
        mandateJti = obj["mandateJti"] as? String
        receiptSeq = obj["receiptSeq"] as? Int
        exercisedScope = (obj["exercisedScope"] as? [String]) ?? []
        withinGrant = obj["withinGrant"] as? Bool ?? false
        receiptChainVerified = obj["receiptChainVerified"] as? Bool ?? false
        reason = obj["reason"] as? String
    }
}
