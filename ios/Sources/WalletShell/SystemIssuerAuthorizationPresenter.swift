#if canImport(AuthenticationServices)
import AuthenticationServices
import Foundation

/// Presents the authorization endpoint in the system authentication session and returns only the
/// callback URL selected by AuthenticationServices. The issuer client independently validates the
/// exact redirect URI, state, and authorization code.
@MainActor
public final class SystemIssuerAuthorizationPresenter: NSObject,
    IssuerAuthorizationPresenting, ASWebAuthenticationPresentationContextProviding
{
    private let anchor: () -> ASPresentationAnchor
    private var activeSession: ASWebAuthenticationSession?

    public init(anchor: @escaping () -> ASPresentationAnchor) {
        self.anchor = anchor
    }

    public func authorize(url: URL, callbackScheme: String) async throws -> URL {
        guard activeSession == nil else { throw IssuerClientError.invalidState }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let session = ASWebAuthenticationSession(
                    url: url,
                    callbackURLScheme: callbackScheme
                ) { [weak self] callback, error in
                    self?.activeSession = nil
                    if let authenticationError = error as? ASWebAuthenticationSessionError,
                       authenticationError.code == .canceledLogin {
                        continuation.resume(throwing: CancellationError())
                    } else if let error {
                        continuation.resume(throwing: error)
                    } else if let callback {
                        continuation.resume(returning: callback)
                    } else {
                        continuation.resume(throwing: IssuerClientError.invalidCallback)
                    }
                }
                session.presentationContextProvider = self
                session.prefersEphemeralWebBrowserSession = true
                activeSession = session
                guard session.start() else {
                    activeSession = nil
                    continuation.resume(throwing: IssuerClientError.invalidState)
                    return
                }
            }
        } onCancel: { [weak self] in
            Task { @MainActor in
                self?.activeSession?.cancel()
                self?.activeSession = nil
            }
        }
    }

    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchor()
    }
}
#endif
