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
        case .consent(let rp, let purpose, let claims):
            ConsentView(rp: rp, purpose: purpose, claims: claims, onConsent: onConsent, onDecline: onDecline)
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
        case .other(let name):
            Text(name)
        }
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
    let onConsent: () -> Void
    let onDecline: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Share information?").font(.title2.bold())
            Text("Requested by \(rp)").font(.subheadline).foregroundStyle(.secondary)
            if !purpose.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                Text(purpose).font(.body)
            }
            Text("Only this information will be shared:").font(.headline).padding(.top, 4)
            ForEach(claims, id: \.self) { claim in
                Label(claim, systemImage: "checkmark.seal")
            }
            Spacer()
            HStack {
                Button("Not now", role: .cancel, action: onDecline)
                Spacer()
                Button("Share information", action: onConsent).buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .accessibilityElement(children: .contain)
    }
}
#endif
