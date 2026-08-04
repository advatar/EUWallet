import SwiftUI

// An original wallet home: a stack of credential cards (a common wallet pattern), rendered with our
// own gradient/typography — no third-party product branding or assets. Card CONTENT comes from the
// real held credential (decoded disclosures + catalogue labels); the actions drive the real core.

extension Color {
    /// Build a Color from a 0xRRGGBB integer.
    init(rgb: UInt32) {
        self.init(
            .sRGB,
            red: Double((rgb >> 16) & 0xFF) / 255,
            green: Double((rgb >> 8) & 0xFF) / 255,
            blue: Double(rgb & 0xFF) / 255,
            opacity: 1)
    }
}

/// A credential rendered as a payment-card-style tile.
struct CredentialCardView: View {
    let credential: WalletCredential
    var body: some View {
        let (a, b) = credential.gradientHex
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(credential.typeName)
                        .font(.headline).foregroundStyle(.white)
                    Text(credential.issuer)
                        .font(.caption).foregroundStyle(.white.opacity(0.8))
                }
                Spacer()
                Image(systemName: "checkmark.seal.fill")
                    .foregroundStyle(.white.opacity(0.9))
            }
            Spacer(minLength: 24)
            HStack(alignment: .bottom) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("NAME").font(.caption2).foregroundStyle(.white.opacity(0.8))
                    Text(credential.holder).font(.title3.weight(.semibold)).foregroundStyle(.white)
                }
                Spacer()
                Image(systemName: "person.text.rectangle.fill")
                    .font(.title2).foregroundStyle(.white.opacity(0.9))
            }
        }
        .padding(20)
        .frame(height: 200)
        .frame(maxWidth: .infinity)
        .background(
            LinearGradient(
                colors: [Color(rgb: a), Color(rgb: b)],
                startPoint: .topLeading, endPoint: .bottomTrailing)
        )
        .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
        .shadow(color: Color(rgb: a).opacity(0.35), radius: 12, x: 0, y: 6)
    }
}

/// The wallet home: cards + primary actions + a toolbar to the other screens. Credentials are
/// obtained through a real OpenID4VCI issuance (the "+" / Add flow) and reflect what the core holds.
struct WalletHomeView: View {
    @ObservedObject var model: WalletModel
    let onPresent: () -> Void
    let onPay: () -> Void
    let onPresentMdoc: () -> Void
    let onOpenHistory: () -> Void
    let onOpenCatalogue: () -> Void
    let onOpenSettings: () -> Void

    @State private var detail: WalletCredential?
    @State private var showAgents = false

    private func openCredentialOffer() {
        model.showConnectSheet = true
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Your documents")
                    .font(.largeTitle.bold())
                    .accessibilityIdentifier("home.title")

                if model.credentials.isEmpty {
                    EmptyWalletView(onAdd: openCredentialOffer)
                } else {
                    ForEach(model.credentials) { credential in
                        Button {
                            detail = credential
                        } label: {
                            CredentialCardView(credential: credential)
                        }
                        .buttonStyle(.plain)
                    }

#if DEBUG
                    HStack(spacing: 12) {
                        ActionButton(title: "Test sharing", systemImage: "qrcode", action: onPresent)
                        ActionButton(title: "Test payment", systemImage: "creditcard", action: onPay)
                    }
#endif
                }

                // Secondary navigation.
                VStack(spacing: 0) {
                    if !model.credentials.isEmpty {
                        WalletRow(title: "Scan a QR code", subtitle: "Add a document or share information",
                                  systemImage: "qrcode.viewfinder", action: { model.showConnectSheet = true })
                        Divider().padding(.leading, 52)
                    }
                    WalletRow(title: "Add from passport", subtitle: "Read your passport or ID chip over NFC",
                              systemImage: "wave.3.right.circle", action: { model.showPassportReader = true })
                    Divider().padding(.leading, 52)
                    WalletRow(title: "Add web evidence", subtitle: "Import a TLSNotary-attested web fact",
                              systemImage: "checkmark.shield", action: { model.showWebEvidence = true })
                    Divider().padding(.leading, 52)
                    WalletRow(title: "Activity", subtitle: model.history.isEmpty ? "Nothing shared yet" : "\(model.history.count) recent actions",
                              systemImage: "list.bullet.rectangle", action: onOpenHistory)
                    Divider().padding(.leading, 52)
                    WalletRow(title: "My Agents",
                              subtitle: model.agentMandates.isEmpty ? "Delegate scoped authority to an AI agent" : "\(model.agentMandates.count) delegated \(model.agentMandates.count == 1 ? "agent" : "agents")",
                              systemImage: "person.badge.key", action: { showAgents = true })
                    Divider().padding(.leading, 52)
                    WalletRow(title: "Settings", subtitle: nil,
                              systemImage: "gear", action: onOpenSettings)
                }
                .background(.quaternary.opacity(0.4))
                .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                .padding(.top, 4)
            }
            .padding(20)
        }
        .overlay {
            if model.isIssuing {
                ProgressView("Adding your document…")
                    .padding(20)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
                    .shadow(radius: 8)
            }
        }
        .consumerPage()
        .sheet(isPresented: $model.showConnectSheet) {
            ConnectView(model: model)
        }
        .sheet(isPresented: $model.showPassportReader) {
            ReadPassportView(reader: ChipmunkPassportReader()) { result in
                model.handlePassportRead(result)
            }
        }
        .sheet(isPresented: $model.showWebEvidence) {
            AddWebEvidenceView(model: model)
        }
        .sheet(item: $detail) { c in
            CredentialDetailView(credential: c, onPresent: {
                detail = nil
                onPresent()
            })
        }
        .sheet(isPresented: $showAgents) {
            MyAgentsView(model: model)
        }
    }
}

/// The "My Agents" screen: the power-of-representation mandates the wallet holds — the scoped,
/// revocable authority the holder has delegated to AI agents. Read-only for now (grant/revoke are
/// issuer/status-list flows); shows on whose behalf each agent acts and exactly which powers it may
/// exercise, so the human stays in control of what an agent can do.
struct MyAgentsView: View {
    @ObservedObject var model: WalletModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Agents act for you, only within the powers you grant — revocable at any time.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .accessibilityIdentifier("agents.intro")

                    if model.agentMandates.isEmpty {
                        VStack(spacing: 12) {
                            ConsumerStatusOrb(systemImage: "person.badge.key")
                            Text("No agents yet").font(.title3.bold())
                            Text("When you delegate a scoped authority to an AI agent, its mandate appears here.")
                                .font(.body).foregroundStyle(ConsumerDesign.mutedInk)
                                .multilineTextAlignment(.center)
                        }
                        .frame(maxWidth: .infinity)
                        .consumerSurface(radius: 20)
                    } else {
                        ForEach(model.agentMandates) { mandate in
                            AgentMandateCard(mandate: mandate)
                        }
                    }
                }
                .padding(20)
            }
            .navigationTitle("My Agents")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task { model.reloadAgentMandates() }
        }
    }
}

/// One agent's mandate: the delegator it represents and the exact powers it may exercise.
private struct AgentMandateCard: View {
    let mandate: AgentMandate

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Image(systemName: "person.badge.key.fill")
                    .font(.title2).foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Acts on behalf of").font(.caption).foregroundStyle(.secondary)
                    Text(mandate.mandator.isEmpty ? "You" : mandate.mandator)
                        .font(.headline).lineLimit(1).truncationMode(.middle)
                }
                Spacer()
                if mandate.revocable {
                    Label("Revocable", systemImage: "xmark.shield")
                        .font(.caption2).foregroundStyle(.secondary)
                        .labelStyle(.titleAndIcon)
                }
            }

            Text("Authorised to")
                .font(.caption).foregroundStyle(.secondary)
            FlowingChips(items: mandate.scopeLabels)

            if let jti = mandate.mandateJti {
                Text("Mandate \(jti)")
                    .font(.caption2.monospaced()).foregroundStyle(.tertiary)
                    .lineLimit(1).truncationMode(.middle)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .consumerSurface(radius: 18)
        .accessibilityElement(children: .combine)
    }
}

/// Simple wrapping row of scope chips.
private struct FlowingChips: View {
    let items: [String]
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(items, id: \.self) { item in
                Text(item)
                    .font(.subheadline.weight(.medium))
                    .padding(.horizontal, 12).padding(.vertical, 6)
                    .background(.tint.opacity(0.14), in: Capsule())
            }
        }
    }
}

/// Shown when the wallet holds nothing yet: a prompt to add the first credential.
private struct EmptyWalletView: View {
    let onAdd: () -> Void
    var body: some View {
        VStack(spacing: 14) {
            ConsumerStatusOrb(systemImage: "wallet.pass.fill")
            Text("Add your first document").font(.title2.bold())
            Text("Keep your ID safely on this phone and choose exactly what to share.")
                .font(.body).foregroundStyle(ConsumerDesign.mutedInk)
                .multilineTextAlignment(.center)
            Button(ConsumerIssuanceEntryPolicy.addActionTitle, action: onAdd)
                .buttonStyle(ConsumerPrimaryButtonStyle())
                .accessibilityIdentifier("home.add")
        }
        .frame(maxWidth: .infinity)
        .consumerSurface(radius: 20)
    }
}

private struct ActionButton: View {
    let title: String
    let systemImage: String
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .font(.headline)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
        }
        .buttonStyle(.borderedProminent)
    }
}

private struct WalletRow: View {
    let title: String
    let subtitle: String?
    let systemImage: String
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: systemImage).font(.body).frame(width: 24).foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title).font(.body).foregroundStyle(.primary)
                    if let subtitle { Text(subtitle).font(.caption).foregroundStyle(.secondary) }
                }
                Spacer()
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary)
            }
            .padding(.vertical, 12).padding(.horizontal, 14)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// A credential's detail: the card plus its decoded claims (labels + values) and a Present action.
struct CredentialDetailView: View {
    let credential: WalletCredential
    let onPresent: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                CredentialCardView(credential: credential).padding(.top, 8)

                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(credential.claims.enumerated()), id: \.offset) { i, claim in
                        if i > 0 { Divider() }
                        HStack {
                            Text(claim.0).foregroundStyle(.secondary)
                            Spacer()
                            Text(claim.1).fontWeight(.medium)
                        }
                        .font(.subheadline)
                        .padding(.vertical, 12)
                    }
                }
                .padding(.horizontal, 16)
                .background(.quaternary.opacity(0.4))
                .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))

                Label("Saved securely on this phone", systemImage: "lock.fill")
                    .font(.caption).foregroundStyle(.secondary)

                Button(action: onPresent) {
                    Label("Use this document", systemImage: "qrcode")
                        .font(.headline).frame(maxWidth: .infinity).padding(.vertical, 12)
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()
        }
    }
}
