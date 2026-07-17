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
                Text(message).font(.body)
                Text(code).font(.caption).foregroundStyle(.secondary)
            }.accessibilityElement(children: .combine)
        case .consent(let rp, let purpose, let claims):
            ConsentView(rp: rp, purpose: purpose, claims: claims, onConsent: onConsent, onDecline: onDecline)
        case .paymentConfirmation(let creditorName, let creditorAccount, let amountMinor, let currency):
            PaymentConfirmationView(
                payee: creditorName, account: creditorAccount, amountMinor: amountMinor,
                currency: currency, onConsent: onConsent, onDecline: onDecline)
        case .other(let name):
            Text(name)
        }
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
        String(format: "%.2f %@", Double(amountMinor) / 100.0, currency)
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
            Text("\(rp) is requesting your data").font(.headline)
            Text("Purpose: \(purpose)").font(.subheadline)
            Text("They will receive only:").font(.subheadline).padding(.top, 4)
            ForEach(claims, id: \.self) { claim in
                Label(claim, systemImage: "checkmark.seal")
            }
            Spacer()
            HStack {
                Button("Decline", role: .cancel, action: onDecline)
                Spacer()
                Button("Share", action: onConsent).buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .accessibilityElement(children: .contain)
    }
}
#endif
