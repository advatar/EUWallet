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
    @State private var showAdd = false

    private var heldTypeNames: Set<String> { Set(model.credentials.map(\.typeName)) }
    private var hasMdoc: Bool { model.credentials.contains { $0.format == "mso_mdoc" } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Your documents")
                    .font(.title2.bold())

                if model.credentials.isEmpty {
                    EmptyWalletView { showAdd = true }
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
                    WalletRow(title: "Scan a QR code", subtitle: "Add a document or share information",
                              systemImage: "qrcode.viewfinder", action: { model.showConnectSheet = true })
                    Divider().padding(.leading, 52)
                    WalletRow(title: "Add a document", subtitle: "Choose an ID or driving licence",
                              systemImage: "plus.circle", action: { showAdd = true })
                    Divider().padding(.leading, 52)
                    WalletRow(title: "Activity", subtitle: model.history.isEmpty ? "Nothing shared yet" : "\(model.history.count) recent actions",
                              systemImage: "list.bullet.rectangle", action: onOpenHistory)
#if DEBUG
                    Divider().padding(.leading, 52)
                    WalletRow(title: "Developer catalogue", subtitle: "Supported test types",
                              systemImage: "hammer", action: onOpenCatalogue)
#endif
                    Divider().padding(.leading, 52)
                    WalletRow(title: "Settings", subtitle: nil,
                              systemImage: "gear", action: onOpenSettings)
                }
                .background(.quaternary.opacity(0.4))
                .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                .padding(.top, 4)
            }
        }
        .overlay {
            if model.isIssuing {
                ProgressView("Adding your document…")
                    .padding(20)
                    .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
                    .shadow(radius: 8)
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showAdd = true } label: { Image(systemName: "plus") }
                    .accessibilityLabel("Add a document")
                    .disabled(model.isIssuing)
            }
        }
        .sheet(isPresented: $showAdd) {
            AddCredentialSheet(heldTypeNames: heldTypeNames) { type in
                model.addCredential(type)
            }
        }
        .sheet(isPresented: $model.showConnectSheet) {
            ConnectView(model: model)
        }
        .sheet(item: $detail) { c in
            CredentialDetailView(credential: c, onPresent: {
                detail = nil
                onPresent()
            })
        }
    }
}

/// Shown when the wallet holds nothing yet: a prompt to add the first credential.
private struct EmptyWalletView: View {
    let onAdd: () -> Void
    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "wallet.pass")
                .font(.system(size: 44)).foregroundStyle(.tint)
            Text("Add your first document").font(.headline)
            Text("Keep your ID safely on this phone and choose exactly what to share.")
                .font(.callout).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button(action: onAdd) {
                Label("Add a document", systemImage: "plus")
                    .font(.headline).padding(.horizontal, 8).padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 32)
    }
}

/// Pick a credential type to be issued. Each choice runs a real OpenID4VCI issuance in the core.
struct AddCredentialSheet: View {
    let heldTypeNames: Set<String>
    let onAdd: (WalletModel.CredentialType) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(WalletModel.CredentialType.allCases) { type in
                        Button {
                            onAdd(type)
                            dismiss()
                        } label: {
                            HStack(spacing: 14) {
                                Image(systemName: type.systemImage)
                                    .font(.title3).frame(width: 30).foregroundStyle(.tint)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(type.displayName).font(.body).foregroundStyle(.primary)
                                    Text(type.subtitle).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if heldTypeNames.contains(type.displayName) {
                                    Image(systemName: "checkmark.circle.fill")
                                        .foregroundStyle(.green)
                                } else {
                                    Image(systemName: "plus.circle").foregroundStyle(.tint)
                                }
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                } footer: {
                    Text("Your document is checked before it is saved. You stay in control of when it is shared.")
                }
            }
            .navigationTitle("Add a document")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
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

                Text("\(credential.id) · stored on-device; shared only with data minimisation.")
                    .font(.caption2).foregroundStyle(.tertiary)

                Button(action: onPresent) {
                    Label("Present this credential", systemImage: "qrcode")
                        .font(.headline).frame(maxWidth: .infinity).padding(.vertical, 12)
                }
                .buttonStyle(.borderedProminent)
            }
            .padding()
        }
    }
}
