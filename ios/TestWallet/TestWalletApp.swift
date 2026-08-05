import SwiftUI

/// A deliberately minimal EUDI test wallet used ONLY to exercise the cross-wallet PID Capture flow:
/// scan/enter an issuer → PIDCapture is launched → this wallet is offered the issued PID and displays
/// it. It stores nothing and does no NFC/liveness itself (that's the PIDCapture companion). Not a
/// production wallet.
@main
struct TestWalletApp: App {
    @StateObject private var model = TestWalletModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
                // The companion hands the PID back same-device via `openid-credential-offer://`.
                .onOpenURL { model.handleIncomingOffer($0) }
        }
    }
}
