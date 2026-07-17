#if canImport(SwiftUI)
import SwiftUI

/// Maps each ScreenDescription archetype to NATIVE, accessible SwiftUI controls.
/// No custom rendering, no layout logic beyond selection — accessibility (Dynamic Type,
/// VoiceOver, EN 301 549 / WCAG 2.2) comes from using system controls (plan Section 8).
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
        case .consent(let c):
            ConsentView(screen: c, onConsent: onConsent, onDecline: onDecline)
        case .credentialList:
            Text("Your credentials").font(.title2)
        default:
            Text("Screen: \(String(describing: screen))")
        }
    }
}

/// The security-critical screen. What the user reads here is what the core hashed and
/// binds the presentation/signature to (what-you-see-is-what-you-sign, plan Section 7).
struct ConsentView: View {
    let screen: ConsentScreen
    let onConsent: () -> Void
    let onDecline: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("\(screen.relyingPartyName) is requesting your data")
                .font(.headline)
            Text("Purpose: \(screen.purpose)")
                .font(.subheadline)
            Text("They will receive only:").font(.subheadline).padding(.top, 4)
            ForEach(screen.requestedClaims, id: \.self) { claim in
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
