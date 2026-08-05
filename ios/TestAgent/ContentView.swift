import SwiftUI

/// TestAgent UI: type a goal → the on-device model proposes the powers it needs → the wallet decides
/// (allow / hold-for-approval / refuse) and shows the receipt. The two columns of the screen are the
/// two layers: the model proposes, the wallet has the authority.
struct TestAgentView: View {
    @ObservedObject var model: TestAgentModel

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("An on-device model proposes what an action needs; the wallet decides whether this agent may do it. The model never holds keys or authority.")
                        .font(.footnote).foregroundStyle(.secondary)
                } header: {
                    Text("Agent ≠ model")
                }

                Section("The agent's mandate") {
                    chips(model.mandate.map { Powers.short(forURN: $0) }, tint: .blue)
                    Text("Delegated to this agent's key. Note: no *administer-account* — an admin goal will be refused.")
                        .font(.caption2).foregroundStyle(.secondary)
                }

                Section("Goal") {
                    TextField("What should the agent do?", text: $model.goal, axis: .vertical)
                        .lineLimit(1...3)
                    Button {
                        Task { await model.plan() }
                    } label: {
                        Label(model.planning ? "Thinking…" : "Ask the model", systemImage: "sparkles")
                    }
                    .disabled(model.planning || model.goal.trimmingCharacters(in: .whitespaces).isEmpty)
                    Text("Planner: \(model.plannerName)")
                        .font(.caption2).foregroundStyle(.secondary)
                }

                if !model.proposed.isEmpty {
                    Section("The model proposes") {
                        chips(model.proposed.map { Powers.short(forURN: $0) }, tint: .purple)
                        Toggle("I approve this action (human step-up)", isOn: $model.humanApproved)
                            .font(.callout)
                        Button {
                            model.exercise()
                        } label: {
                            Label("Exercise via the wallet", systemImage: "checkmark.shield")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }

                if let r = model.result {
                    Section("The wallet decided") { resultView(r) }
                }
            }
            .navigationTitle("PID Test Agent")
        }
    }

    @ViewBuilder private func resultView(_ r: AgentResult) -> some View {
        switch r.decision {
        case "signed":
            Label("Signed on behalf of the delegator", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green).font(.headline)
            row("Required tier", r.requiredTier ?? "—")
            if r.steppedUp { row("Human step-up", r.heldForApproval ? "held, then approved" : "approved") }
            row("On behalf of", r.onBehalfOf ?? "—")
            if let jti = r.mandateJti { row("Mandate", jti) }
            if let seq = r.receiptSeq { row("Receipt #", String(seq)) }
            row("Within grant", r.withinGrant ? "yes ✓" : "NO ✗")
            row("Receipt chain", r.receiptChainVerified ? "verified ✓" : "INVALID ✗")
        default:
            Label("Refused", systemImage: "xmark.octagon.fill")
                .foregroundStyle(.red).font(.headline)
            row("Stage", r.stage == "signing" ? "signing (needs approval)" : "selection (out of scope)")
            row("Required tier", r.requiredTier ?? "—")
            if let reason = r.reason {
                Text(reason).font(.footnote).foregroundStyle(.secondary)
            }
            if r.stage == "signing" {
                Text("Turn on “I approve this action” and exercise again.")
                    .font(.caption2).foregroundStyle(.secondary)
            }
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack {
            Text(k).foregroundStyle(.secondary)
            Spacer()
            Text(v).multilineTextAlignment(.trailing)
        }
        .font(.callout)
    }

    private func chips(_ labels: [String], tint: Color) -> some View {
        FlowChips(labels: labels, tint: tint)
    }
}

/// A simple wrapping row of pill labels.
private struct FlowChips: View {
    let labels: [String]
    let tint: Color
    var body: some View {
        WrapHStack(labels) { label in
            Text(label)
                .font(.caption).monospaced()
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(tint.opacity(0.15), in: Capsule())
                .foregroundStyle(tint)
        }
    }
}

/// Minimal wrapping HStack (avoids a Layout dependency): lays chips in rows that wrap.
private struct WrapHStack<Content: View>: View {
    let items: [String]
    let content: (String) -> Content
    init(_ items: [String], @ViewBuilder content: @escaping (String) -> Content) {
        self.items = items
        self.content = content
    }
    var body: some View {
        // A LazyVGrid with adaptive columns wraps chips without manual geometry.
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 110), spacing: 6, alignment: .leading)], alignment: .leading, spacing: 6) {
            ForEach(items, id: \.self) { content($0) }
        }
    }
}
