import Foundation

#if canImport(FoundationModels)
    import FoundationModels
#endif

/// The six delegated powers, mapped short-name ↔ URN, with natural-language hints the offline planner
/// keys off. Mirrors `POWER_TAXONOMY` in issuer-core / the wallet-core delegation gate.
enum Powers {
    struct Power {
        let short: String
        let urn: String
        let keywords: [String]
    }

    static let all: [Power] = [
        Power(
            short: "present-identity",
            urn: "urn:eudi:mandate:power:present-identity",
            keywords: ["prove", "identity", "who i am", "age", "over 18", "over-18", "log in", "login", "sign in", "verify"]),
        Power(
            short: "sign-document",
            urn: "urn:eudi:mandate:power:sign-document",
            keywords: ["sign", "e-sign", "signature", "agreement", "contract", "document"]),
        Power(
            short: "authorise-payment",
            urn: "urn:eudi:mandate:power:authorise-payment",
            keywords: ["pay", "payment", "purchase", "buy", "checkout", "transfer money", "€", "eur"]),
        Power(
            short: "manage-subscription",
            urn: "urn:eudi:mandate:power:manage-subscription",
            keywords: ["subscribe", "subscription", "cancel plan", "renew", "plan"]),
        Power(
            short: "access-records",
            urn: "urn:eudi:mandate:power:access-records",
            keywords: ["read", "records", "history", "statement", "view data", "access"]),
        Power(
            short: "administer-account",
            urn: "urn:eudi:mandate:power:administer-account",
            keywords: ["settings", "admin", "close account", "add payee", "change password", "manage account"]),
    ]

    static func short(forURN urn: String) -> String {
        all.first { $0.urn == urn }?.short ?? urn
    }
    static func urn(forShort short: String) -> String? {
        all.first { $0.short == short }?.urn
    }
}

/// The MODEL layer of the TestAgent. It turns a natural-language goal into the delegated powers an
/// action *needs* — it only **proposes**. The wallet (`exerciseMandate`) is the one that decides
/// whether the agent may exercise them. Keeping these separate is the whole point ("the agent is not
/// the model"): the model holds no keys and no authority.
protocol AgentPlanner: Sendable {
    /// Human-readable name shown in the UI.
    var name: String { get }
    /// Propose the power URNs a goal requires.
    func propose(goal: String) async -> [String]
}

/// Deterministic offline planner: keyword-matches the goal to powers. The Simulator (and any device
/// without Apple Intelligence) falls back to this, so the flow always runs.
struct KeywordPlanner: AgentPlanner {
    let name = "Keyword planner (offline)"

    func propose(goal: String) async -> [String] {
        let g = goal.lowercased()
        var urns = Powers.all
            .filter { power in power.keywords.contains { g.contains($0) } }
            .map(\.urn)
        if urns.isEmpty {
            urns = [Powers.all[0].urn]  // default: present an identity
        }
        return urns
    }
}

#if canImport(FoundationModels)
    /// The on-device LLM planner (Apple Foundation Models). Available on Apple-Intelligence-capable
    /// devices running iOS 26+. It proposes powers as structured output; it never holds authority.
    @available(iOS 26.0, *)
    struct FoundationModelsPlanner: AgentPlanner {
        let name = "Apple Foundation Models (on-device)"

        /// Structured proposal the model is constrained to produce.
        @Generable
        struct Proposal {
            @Guide(description: "The delegated powers this goal needs, chosen only from the allowed short names.")
            var powers: [String]
        }

        func propose(goal: String) async -> [String] {
            let allowed = Powers.all.map(\.short).joined(separator: ", ")
            let session = LanguageModelSession(
                instructions: """
                You map a user's goal to the MINIMAL set of delegated powers it requires.
                Allowed powers (use these exact short names only): \(allowed).
                Return only powers from that list; prefer the fewest that satisfy the goal.
                """)
            do {
                let reply = try await session.respond(to: goal, generating: Proposal.self)
                let urns = reply.content.powers.compactMap { Powers.urn(forShort: $0) }
                return urns.isEmpty ? [Powers.all[0].urn] : urns
            } catch {
                // Fall back to the offline planner if the model is unavailable at runtime.
                return await KeywordPlanner().propose(goal: goal)
            }
        }
    }
#endif

/// Pick the best available planner: the on-device model when the framework + OS support it,
/// otherwise the offline keyword planner.
func makePlanner() -> AgentPlanner {
    #if canImport(FoundationModels)
        if #available(iOS 26.0, *) {
            return FoundationModelsPlanner()
        }
    #endif
    return KeywordPlanner()
}
