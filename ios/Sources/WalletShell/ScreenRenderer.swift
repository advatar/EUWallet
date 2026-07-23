#if canImport(SwiftUI)
import SwiftUI

/// Maps each ScreenDescription archetype to NATIVE, accessible SwiftUI controls. No custom
/// rendering — accessibility (Dynamic Type, VoiceOver, EN 301 549 / WCAG 2.2) comes from using
/// system controls (plan Section 8).
public struct ScreenRenderer: View {
    public let screen: ScreenDescription
    public let onConsent: () -> Void
    public let onDecline: () -> Void

    public init(screen: ScreenDescription, onConsent: @escaping () -> Void, onDecline: @escaping () -> Void) {
        self.screen = screen
        self.onConsent = onConsent
        self.onDecline = onDecline
    }

    public var body: some View {
        content.consumerPage()
    }

    @ViewBuilder private var content: some View {
        switch screen {
        case .loading:
            ProgressView("Loading…")
        case .error(let code, let message):
            VStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle").font(.largeTitle)
                Text("Something went wrong").font(.headline)
                Text("Please try again. Nothing was shared.").font(.body)
#if DEBUG
                Text(message).font(.caption).foregroundStyle(.secondary)
                Text(code).font(.caption).foregroundStyle(.secondary)
#endif
            }.accessibilityElement(children: .combine)
        case .consent(
            let rp,
            let purpose,
            let claims,
            let notSharedClaims,
            let verifierRegistration,
            let trustMark,
            let retention,
            let overAsk):
            ConsentView(
                rp: rp,
                purpose: purpose,
                claims: claims,
                notSharedClaims: notSharedClaims,
                verifierRegistration: verifierRegistration,
                trustMark: trustMark,
                retention: retention,
                overAsk: overAsk,
                onConsent: onConsent,
                onDecline: onDecline)
        case .paymentConfirmation(let creditorName, let creditorAccount, let amountMinor, let currency):
            PaymentConfirmationView(
                payee: creditorName, account: creditorAccount, amountMinor: amountMinor,
                currency: currency, onConsent: onConsent, onDecline: onDecline)
        case .signConfirmation(let documentName, let qtspId, let documentHashHex):
            SignConfirmationView(
                documentName: documentName,
                qtspId: qtspId,
                documentHashHex: documentHashHex,
                onConsent: onConsent,
                onDecline: onDecline)
        case .credentialList(let list):
            DocumentListView(documents: list.documents)
        case .credentialDetail(let detail):
            DocumentDetailScreenView(detail: detail, onUse: onConsent)
        case .issuanceOffer(let offer):
            IssuanceOfferView(offer: offer, onAdd: onConsent, onDecline: onDecline)
        case .pinPreparation(let documentName):
            PinPreparationView(documentName: documentName, onContinue: onConsent, onHelp: onDecline)
        case .pinHelp:
            PinHelpView(onContinue: onConsent, onBack: onDecline)
        case .nfcReady(let documentName):
            NfcReadyView(documentName: documentName, onContinue: onConsent, onCancel: onDecline)
        case .nfcReading(let state):
            NfcReadingView(state: state, onCancel: onDecline)
        case .issuancePreparing(let document):
            IssuanceStatusView(document: document, ready: false, onDone: onConsent)
        case .issuanceReady(let document):
            IssuanceStatusView(document: document, ready: true, onDone: onConsent)
        case .issuanceNeedsAttention(let document, let recovery):
            IssuanceNeedsAttentionView(document: document, recovery: recovery, onContinue: onConsent)
        case .issuanceRecovery(let recovery):
            IssuanceRecoveryView(recovery: recovery, onPrimary: onConsent, onSecondary: onDecline)
        case .other(let name):
            Text(name)
        }
    }
}

private struct DocumentBadge: View {
    let document: DocumentSummary
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(document.documentName).font(.title3.bold())
            Text(document.issuerName).font(.subheadline).foregroundStyle(.secondary)
            Label(statusText, systemImage: statusIcon).font(.subheadline.weight(.semibold))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(20)
        .foregroundStyle(.white)
        .background(
            LinearGradient(
                colors: [ConsumerDesign.brandInk, ConsumerDesign.brand],
                startPoint: .topLeading,
                endPoint: .bottomTrailing),
            in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .shadow(color: ConsumerDesign.brandInk.opacity(0.22), radius: 16, y: 8)
        .accessibilityElement(children: .combine)
    }
    private var statusText: String {
        switch document.status { case .preparing: "Preparing"; case .ready: "Ready"; case .needsAttention: "Needs attention" }
    }
    private var statusIcon: String {
        switch document.status { case .preparing: "clock"; case .ready: "checkmark.circle.fill"; case .needsAttention: "exclamationmark.circle.fill" }
    }
}

private struct DocumentListView: View {
    let documents: [DocumentSummary]
    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 16) {
                Text("Your documents").font(.largeTitle.bold())
                ForEach(documents) { DocumentBadge(document: $0) }
            }.padding(20)
        }
            .navigationTitle("Your documents")
    }
}

private struct DocumentDetailScreenView: View {
    let detail: CredentialDetailScreen
    let onUse: () -> Void
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                DocumentBadge(document: detail.document)
                ForEach(Array(detail.attributes.enumerated()), id: \.offset) { _, item in
                    LabeledContent(item.label, value: item.value)
                }
                Label("Kept securely on this phone", systemImage: "lock.fill").foregroundStyle(.secondary)
                Button("Use this document", action: onUse).buttonStyle(ConsumerPrimaryButtonStyle())
            }.padding()
        }
    }
}

private struct IssuanceOfferView: View {
    let offer: IssuanceOfferScreen
    let onAdd: () -> Void
    let onDecline: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("ADD A DOCUMENT").font(.caption.weight(.bold)).tracking(1.5).foregroundStyle(ConsumerDesign.brand)
            Text("Add your \(offer.documentName)").font(.largeTitle.bold())
            HStack(spacing: 12) {
                Image(systemName: "checkmark.seal.fill").foregroundStyle(ConsumerDesign.good)
                VStack(alignment: .leading, spacing: 2) {
                    Text(offer.issuerName).font(.headline)
                    Text("Verified issuer").font(.subheadline).foregroundStyle(ConsumerDesign.good)
                }
            }.consumerSurface()
            Text("Use this document to prove who you are when you choose.").foregroundStyle(.secondary)
            DisclosureGroup("What will be added") {
                ForEach(offer.attributes.filter { $0 != "portrait" }, id: \.self) {
                    Label(ConsumerCopy.claimName($0), systemImage: "checkmark")
                }
                if offer.portraitRequired { Label("Portrait", systemImage: "person.crop.rectangle") }
            }
            Spacer()
            Button("Add document", action: onAdd).buttonStyle(ConsumerPrimaryButtonStyle())
            Button("Not now", role: .cancel, action: onDecline).buttonStyle(ConsumerSecondaryButtonStyle())
        }.padding(20)
    }
}

private struct PinPreparationView: View {
    let documentName: String; let onContinue: () -> Void; let onHelp: () -> Void
    var body: some View { JourneyChoiceView(title: "Do you know your ID card PIN?", message: "The 6-digit PIN you chose for your ID card. You’ll enter it when you tap the card.", icon: "number.square", primary: "Yes, I know it", secondary: "I’m not sure", onPrimary: onContinue, onSecondary: onHelp) }
}
private struct PinHelpView: View {
    let onContinue: () -> Void; let onBack: () -> Void
    var body: some View { JourneyChoiceView(title: "Finding your PIN", message: "Your PIN is the 6 digits you set when you activated your ID card. If you only have the letter, you can set or reset your PIN before continuing.", icon: "questionmark.circle", primary: "I’ve got it — continue", secondary: "Back", onPrimary: onContinue, onSecondary: onBack) }
}
private struct NfcReadyView: View {
    let documentName: String; let onContinue: () -> Void; let onCancel: () -> Void
    var body: some View { JourneyChoiceView(title: "Hold your card to the top of your phone", message: "Keep it still while your phone reads the card. You can cancel at any time.", icon: "wave.3.right.circle", primary: "I’m ready", secondary: "Cancel", onPrimary: onContinue, onSecondary: onCancel) }
}
private struct NfcReadingView: View {
    let state: NfcReadState; let onCancel: () -> Void
    var body: some View {
        VStack(spacing: 24) {
            ConsumerStatusOrb(
                systemImage: state == .connectionLost ? "iphone.slash" : "wave.3.right.circle.fill",
                tint: state == .connectionLost ? ConsumerDesign.warning : ConsumerDesign.brand,
                background: state == .connectionLost ? ConsumerDesign.warningBackground : nil)
            Text(state == .connectionLost ? "Move the card back into place" : state == .reading ? "Reading your card" : "Waiting for your card").font(.largeTitle.bold()).multilineTextAlignment(.center)
            Text(state == .connectionLost ? "Nothing was lost. Hold it at the top of your phone to continue." : "Keep the card still until this finishes.").foregroundStyle(.secondary).multilineTextAlignment(.center)
            ProgressView().accessibilityLabel(state == .connectionLost ? "Connection interrupted" : "Reading card")
            Spacer(); Button("Cancel", role: .cancel, action: onCancel).frame(minHeight: 44)
        }.padding(20).accessibilityElement(children: .contain)
    }
}
private struct IssuanceStatusView: View {
    let document: DocumentSummary; let ready: Bool; let onDone: () -> Void
    var body: some View {
        VStack(spacing: 22) {
            ConsumerStatusOrb(
                systemImage: ready ? "checkmark" : "clock.fill",
                tint: ready ? ConsumerDesign.good : ConsumerDesign.brand,
                background: ready ? ConsumerDesign.goodBackground : nil)
            Text(ready ? "Your \(document.documentName) is ready" : "Preparing your \(document.documentName)").font(.largeTitle.bold()).multilineTextAlignment(.center)
            if ready { DocumentBadge(document: document) } else { Text("We’ll let you know when it’s ready. You can close the app.").foregroundStyle(.secondary).multilineTextAlignment(.center) }
            Spacer()
            Button(ready ? "Go to Wallet" : "Done", action: onDone)
                .buttonStyle(ConsumerPrimaryButtonStyle())
        }.padding(20)
    }
}
private struct IssuanceNeedsAttentionView: View {
    let document: DocumentSummary; let recovery: IssuanceRecovery; let onContinue: () -> Void
    var body: some View { JourneyChoiceView(title: "One quick step to finish", message: "Your progress is saved. Continue when you’re ready.", icon: "exclamationmark.circle", primary: "Continue", secondary: "Later", onPrimary: onContinue, onSecondary: {}) }
}
private struct IssuanceRecoveryView: View {
    let recovery: IssuanceRecoveryScreen; let onPrimary: () -> Void; let onSecondary: () -> Void
    var body: some View {
        JourneyChoiceView(title: title, message: message, icon: "exclamationmark.circle", primary: recovery.canResume ? "Continue" : "See what you can do", secondary: "Later", onPrimary: onPrimary, onSecondary: onSecondary)
    }
    private var title: String { switch recovery.reason { case .wrongPin: "That PIN didn’t match"; case .pinBlocked: "Your card PIN is blocked"; case .nfcInterrupted: "The card moved away"; case .nfcUnavailable: "This phone can’t read your card"; case .issuerRejected: "The document couldn’t be added"; case .networkInterrupted: "The connection was interrupted"; case .delayed: "Your document is still being prepared"; case .sessionInterrupted: "Continue adding your document" } }
    private var message: String { if let attempts = recovery.attemptsRemaining { return "You have \(attempts) tries left. Take your time." }; return recovery.canResume ? "Your progress is saved, so you can continue where you left off." : "Nothing was added. Your existing wallet information is safe." }
}
private struct JourneyChoiceView: View {
    let title: String; let message: String; let icon: String; let primary: String; let secondary: String
    let onPrimary: () -> Void; let onSecondary: () -> Void
    var body: some View {
        VStack(spacing: 20) {
            ConsumerStatusOrb(systemImage: icon)
            Text(title).font(.largeTitle.bold()).multilineTextAlignment(.center)
            Text(message).font(.title3).foregroundStyle(ConsumerDesign.mutedInk).multilineTextAlignment(.center)
            Spacer()
            Button(primary, action: onPrimary).buttonStyle(ConsumerPrimaryButtonStyle())
            Button(secondary, action: onSecondary).buttonStyle(ConsumerSecondaryButtonStyle())
        }.padding(20)
    }
}

struct SignConfirmationView: View {
    let documentName: String
    let qtspId: String
    let documentHashHex: String
    let onConsent: () -> Void
    let onDecline: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Sign this document?").font(.headline)
            Text(documentName).font(.title2.bold())
            Text("Signing service: \(qtspId)").font(.subheadline)
#if DEBUG
            Text("Document hash: \(documentHashHex)")
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
#endif
            Spacer()
            HStack {
                Button("Cancel", role: .cancel, action: onDecline)
                Spacer()
                Button("Sign", action: onConsent).buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .accessibilityElement(children: .contain)
    }
}

/// The payment SCA screen — deliberately distinct from the identity consent screen. Shows exactly
/// the amount and payee the user is authorising (what-you-see-is-what-you-authorise).
struct PaymentConfirmationView: View {
    let payee: String
    let account: String
    let amountMinor: UInt64
    let currency: String
    let onConsent: () -> Void
    let onDecline: () -> Void

    private var amountText: String {
        Self.exactAmountText(amountMinor: amountMinor, currency: currency)
    }

    nonisolated static func exactAmountText(amountMinor: UInt64, currency: String) -> String {
        let major = amountMinor / 100
        let minor = amountMinor % 100
        let minorText = minor < 10 ? "0\(minor)" : "\(minor)"
        return "\(major).\(minorText) \(currency)"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Confirm payment").font(.headline)
            Text(amountText).font(.largeTitle.bold())
            Text("to \(payee)").font(.subheadline)
            Text(account).font(.caption).foregroundStyle(.secondary)
            Spacer()
            HStack {
                Button("Cancel", role: .cancel, action: onDecline)
                Spacer()
                Button("Pay \(amountText)", action: onConsent).buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .accessibilityElement(children: .contain)
    }
}

/// The security-critical screen. What the user reads here is what the core hashed and binds the
/// presentation/signature to (what-you-see-is-what-you-sign, plan Section 7).
struct ConsentView: View {
    let rp: String
    let purpose: String
    let claims: [String]
    let notSharedClaims: [String]
    let verifierRegistration: VerifierRegistration
    let trustMark: VerifierTrustMark?
    let retention: RetentionDisclosure
    let overAsk: OverAskResult
    let onConsent: () -> Void
    let onDecline: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                Text(overAsk.result == .exceedsRegisteredScope ? "Check this request" : "Share with \(rp)?")
                    .font(.largeTitle.bold())
                    .accessibilityAddTraits(.isHeader)

                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: "checkmark.shield.fill")
                        .font(.title2)
                        .foregroundStyle(ConsumerDesign.good)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(rp).font(.headline)
                        Text(
                            verifierRegistration == .registered
                                ? "Registered verifier" : "Identity certificate verified")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(ConsumerDesign.good)
                        if !purpose.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                            Text(purpose).font(.subheadline).foregroundStyle(ConsumerDesign.mutedInk)
                        }
                    }
                    Spacer()
                }
                .consumerSurface()

                if trustMark == .eudiWallet {
                    Label("EU Digital Identity trust mark", systemImage: "checkmark.seal.fill")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(ConsumerDesign.good)
                }

                if overAsk.result == .exceedsRegisteredScope {
                    Label(
                        "This request asks for more information than the verifier is registered to need.",
                        systemImage: "exclamationmark.triangle.fill")
                        .font(.headline)
                        .foregroundStyle(ConsumerDesign.warning)
                        .padding(16)
                        .background(
                            ConsumerDesign.warningBackground,
                            in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .accessibilityLabel(
                            "Warning: This request asks for more information than the verifier is registered to need.")
                }

                Text("Sharing").font(.headline)
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(claims.enumerated()), id: \.offset) { index, claim in
                        if index > 0 { Divider() }
                        Label(ConsumerCopy.claimName(claim), systemImage: "checkmark")
                            .font(.body.weight(.semibold))
                            .foregroundStyle(ConsumerDesign.ink)
                            .padding(.vertical, 12)
                    }
                }
                .padding(.horizontal, 16)
                .background(ConsumerDesign.surfaceRaised, in: RoundedRectangle(cornerRadius: 14))

                retentionLabel

                if !notSharedClaims.isEmpty {
                    Text("Stays in your wallet").font(.headline)
                    Text(notSharedClaims.map(ConsumerCopy.claimName).joined(separator: ", "))
                        .foregroundStyle(ConsumerDesign.mutedInk)
                        .padding(16)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(ConsumerDesign.surfaceRaised, in: RoundedRectangle(cornerRadius: 14))
                }

                if overAsk.result == .exceedsRegisteredScope {
                    Button("Don’t share", role: .cancel, action: onDecline)
                        .buttonStyle(ConsumerPrimaryButtonStyle())
                    Button("Share only this information", action: onConsent)
                        .buttonStyle(ConsumerSecondaryButtonStyle())
                } else {
                    Button("Approve and share", action: onConsent)
                        .buttonStyle(ConsumerPrimaryButtonStyle())
                    Button("Don’t share", role: .cancel, action: onDecline)
                        .buttonStyle(ConsumerSecondaryButtonStyle())
                }
            }
            .padding(20)
        }
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder private var retentionLabel: some View {
        switch retention.policy {
        case .notStored:
            Label("The verifier says it will not store this information", systemImage: "clock.badge.xmark")
                .font(.subheadline)
        case .days:
            if let days = retention.days {
                Label("The verifier may keep it for \(days) days", systemImage: "calendar")
                    .font(.subheadline)
            }
        case .unspecified:
            Label("The verifier has not said how long it will keep this information", systemImage: "questionmark.circle")
                .font(.subheadline)
        }
    }
}
#endif
