import Foundation
import SwiftUI

#if canImport(UIKit)
    import UIKit
#endif

/// Drives the test wallet's three-step flow: create a session bound to a fresh key → launch the
/// PIDCapture companion → be offered the issued PID (via the companion's same-device deep-link
/// hand-off, or by polling the session) → display it. Nothing is retained.
@MainActor
final class TestWalletModel: ObservableObject {
    enum Phase: Equatable {
        case idle
        case creating
        case awaiting
        case displaying
        case failed(String)
    }

    @Published var issuerURL = "https://issuer.advatar.systems"
    @Published private(set) var phase: Phase = .idle
    @Published private(set) var claims: [PidClaim] = []
    @Published private(set) var sessionID: String?

    private var pollTask: Task<Void, Never>?

    /// Step 1–2: create the capture session with this wallet's key and launch the companion.
    func start() {
        let trimmed = issuerURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let base = URL(string: trimmed), base.scheme != nil else {
            phase = .failed("Enter a valid issuer URL (e.g. https://issuer.advatar.systems).")
            return
        }
        pollTask?.cancel()
        claims = []
        phase = .creating
        let client = CaptureClient(issuerBaseURL: base)
        let holder = HolderKey()
        Task {
            do {
                let created = try await client.createSession(holderJwk: holder.publicJwk)
                self.sessionID = created.sessionID
                if let url = URL(string: created.invocationURL) {
                    #if canImport(UIKit)
                        _ = await UIApplication.shared.open(url)  // launch PIDCapture (same device)
                    #endif
                }
                self.phase = .awaiting
                self.poll(client: client, sessionID: created.sessionID)
            } catch {
                self.phase = .failed(error.localizedDescription)
            }
        }
    }

    /// Step 3 (cross-device / fallback): poll the session until the PID is issued.
    private func poll(client: CaptureClient, sessionID: String) {
        pollTask = Task {
            for _ in 0..<150 {  // ~5 minutes at 2s
                if Task.isCancelled { return }
                if let result = try? await client.fetchResult(sessionID: sessionID),
                    result.status == "issued", let credential = result.credential
                {
                    self.display(credential: credential)
                    return
                }
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
            if case .awaiting = self.phase {
                self.phase = .failed("Timed out waiting for the PID.")
            }
        }
    }

    /// Step 3 (same device): the companion opened `openid-credential-offer://…` back into this app.
    func handleIncomingOffer(_ url: URL) {
        guard url.scheme == "openid-credential-offer",
            let credential = PidDisplay.credential(fromOfferURL: url)
        else { return }
        display(credential: credential)
    }

    func reset() {
        pollTask?.cancel()
        claims = []
        sessionID = nil
        phase = .idle
    }

    private func display(credential: String) {
        pollTask?.cancel()
        claims = PidDisplay.claims(fromSdJwt: credential)
        phase = .displaying
    }
}
