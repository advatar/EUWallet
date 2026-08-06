import ExtensionKit
import IdentityDocumentServices
import IdentityDocumentServicesUI
import SwiftUI

/// System-hosted authorization UI for Digital Credentials API (OpenID4VP-over-DC-API) presentment.
///
/// When a website calls `navigator.credentials.get({digital})` for an ISO 18013 mobile document,
/// iOS hosts this extension. The holder sees who is asking and taps **Share**; the extension then
/// drives the real Rust wallet core to produce a minimised, handover-bound `DeviceResponse` and
/// returns it to the browser via `sendResponse`.
///
/// This first release is deliberately **self-contained and demo-seeded** (see
/// `DcApiPresentationDriver`): it presents a demo PID mdoc signed by a key it fully controls, so the
/// response is genuinely verifiable end to end without the security-critical shared-store / shared-
/// keychain migration that would let it present the holder's *actual* app-provisioned credentials.
/// That migration is tracked separately and must be validated with the device in the loop.
@main
struct EUWalletDocumentProvider: IdentityDocumentProvider {
    var body: some IdentityDocumentRequestScene {
        ISO18013MobileDocumentRequestScene { context in
            ProviderAuthorizationView(
                requestingOrigin: context.requestingWebsiteOrigin,
                sendResponse: context.sendResponse,
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
    /// Bound from `ISO18013MobileDocumentRequestContext.sendResponse` — invoked once the holder
    /// authorizes, with a handler that yields the wallet's response for the OS-validated raw request.
    let sendResponse:
        (@escaping @Sendable (IdentityDocumentWebPresentmentRawRequest) async throws ->
            ISO18013MobileDocumentResponse) async throws -> Void
    let cancel: @MainActor () -> Void

    @State private var status: Status = .idle

    private enum Status: Equatable {
        case idle
        case sharing
        case shared
        case failed(String)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Image(systemName: "person.text.rectangle")
                .font(.system(size: 42))
                .foregroundStyle(.blue)
                .accessibilityHidden(true)

            Text("Identity request")
                .font(.largeTitle.bold())

            Text(originDescription)
                .font(.body)
                .foregroundStyle(.secondary)

            switch status {
            case .idle:
                Text("Your digital identity (PID) will be shared. Only the details this website asked for are disclosed.")
                    .font(.body)
            case .sharing:
                HStack(spacing: 10) {
                    ProgressView()
                    Text("Sharing your identity…").font(.body)
                }
            case .shared:
                Label("Shared successfully", systemImage: "checkmark.seal.fill")
                    .font(.body).foregroundStyle(.green)
            case .failed(let message):
                Label(message, systemImage: "xmark.octagon.fill")
                    .font(.body).foregroundStyle(.red)
                    .accessibilityLabel("Could not share: \(message)")
            }

            Spacer()

            if status != .shared {
                Button(action: share) {
                    Text("Share").frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(status == .sharing)
                .accessibilityHint("Shares your digital identity with \(hostLabel)")

                Button("Not now", role: .cancel, action: cancel)
                    .controlSize(.large)
                    .frame(maxWidth: .infinity)
                    .disabled(status == .sharing)
                    .accessibilityHint("Closes this identity request without sharing information")
            }
        }
        .padding(24)
    }

    private func share() {
        status = .sharing
        let originURL = requestingOrigin
        Task { @MainActor in
            do {
                try await sendResponse { rawRequest in
                    try await Self.respond(to: rawRequest, requestingOrigin: originURL)
                }
                status = .shared
            } catch {
                status = .failed(Self.userMessage(for: error))
            }
        }
    }

    /// Produce the wallet's response for the OS-validated raw request. Static + capturing only the
    /// `Sendable` origin URL, so the `@Sendable` response handler carries no view state across the
    /// concurrency boundary.
    @Sendable
    private static func respond(
        to rawRequest: IdentityDocumentWebPresentmentRawRequest,
        requestingOrigin: URL?
    ) async throws -> ISO18013MobileDocumentResponse {
        #if canImport(wallet_coreFFI)
            guard rawRequest.requestType == .iso18013MobileDocument else {
                throw ProviderError.unsupportedRequestType
            }
            guard let originURL = requestingOrigin else {
                throw ProviderError.missingOrigin
            }
            // Defense in depth: Apple's validator independently confirms the request is a well-formed
            // ISO 18013 mobile-document request bound to this Origin before the core sees it.
            _ = try IdentityDocumentWebPresentmentRawRequestValidator()
                .validateISO18013MobileDocumentRequest(rawRequest.requestData, origin: originURL)

            let driver = try DcApiPresentationDriver()
            try await driver.seedIfNeeded()
            let responseData = try driver.present(
                requestData: rawRequest.requestData,
                origin: webOrigin(from: originURL))
            return ISO18013MobileDocumentResponse(responseData: responseData)
        #else
            throw ProviderError.coreUnavailable
        #endif
    }

    /// W3C Origin serialization (`scheme://host[:port]`, default ports omitted) — the exact string
    /// the verifier bound into the `OpenID4VPDCAPIHandover`, so the core's `DeviceAuthentication`
    /// matches byte for byte.
    private static func webOrigin(from url: URL) -> String {
        guard let scheme = url.scheme?.lowercased(), let host = url.host() else {
            return url.absoluteString
        }
        let isDefaultPort = (scheme == "https" && url.port == 443) || (scheme == "http" && url.port == 80)
        if let port = url.port, !isDefaultPort {
            return "\(scheme)://\(host):\(port)"
        }
        return "\(scheme)://\(host)"
    }

    private static func userMessage(for error: Error) -> String {
        #if canImport(wallet_coreFFI)
            if let driverError = error as? DcApiPresentationDriver.DriverError {
                return driverError.description
            }
        #endif
        if let providerError = error as? ProviderError {
            return providerError.description
        }
        return "We couldn't share your identity. Please try again."
    }

    private var hostLabel: String { requestingOrigin?.host() ?? "this website" }

    private var originDescription: String {
        guard let host = requestingOrigin?.host(), !host.isEmpty else {
            return "A website is asking for information from an identity document."
        }
        return "\(host) is asking for information from an identity document."
    }
}

private enum ProviderError: Error, CustomStringConvertible {
    case unsupportedRequestType
    case missingOrigin
    case coreUnavailable

    var description: String {
        switch self {
        case .unsupportedRequestType:
            return "This request type is not supported."
        case .missingOrigin:
            return "The request did not identify the requesting website."
        case .coreUnavailable:
            return "The wallet engine is unavailable in this build."
        }
    }
}
