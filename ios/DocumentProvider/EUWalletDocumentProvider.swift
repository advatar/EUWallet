import ExtensionKit
import IdentityDocumentServicesUI
import SwiftUI

/// System-hosted authorization UI for Digital Credentials API presentment.
///
/// The first release is deliberately fail-closed: it proves and packages Apple's required
/// provider contract while preventing an unverified request from releasing a credential. The
/// verified raw-request-to-Rust-response adapter tracked in #66 will replace the unavailable
/// action without changing the extension boundary.
@main
struct EUWalletDocumentProvider: IdentityDocumentProvider {
    var body: some IdentityDocumentRequestScene {
        ISO18013MobileDocumentRequestScene { context in
            ProviderAuthorizationView(
                requestingOrigin: context.requestingWebsiteOrigin,
                cancel: context.cancel
            )
        }
    }

    func performRegistrationUpdates() async {
        // Registrations are driven by authenticated wallet storage. Never invent registrations
        // from the extension before the shared durable document catalogue is available.
    }
}

private struct ProviderAuthorizationView: View {
    let requestingOrigin: URL?
    let cancel: @MainActor () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Image(systemName: "person.text.rectangle.and.nfc")
                .font(.system(size: 42))
                .foregroundStyle(.blue)
                .accessibilityHidden(true)

            Text("Identity request")
                .font(.largeTitle.bold())

            Text(originDescription)
                .font(.body)
                .foregroundStyle(.secondary)

            Text("EU Wallet cannot share this document until the request has been fully verified.")
                .font(.body)

            Spacer()

            Button("Not now", role: .cancel, action: cancel)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .frame(maxWidth: .infinity)
                .accessibilityHint("Closes this identity request without sharing information")
        }
        .padding(24)
    }

    private var originDescription: String {
        guard let host = requestingOrigin?.host(), !host.isEmpty else {
            return "A website is asking for information from an identity document."
        }
        return "\(host) is asking for information from an identity document."
    }
}
