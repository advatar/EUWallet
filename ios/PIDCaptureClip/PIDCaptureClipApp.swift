import CaptureKit
import SwiftUI

/// PID Capture App Clip: the same reader-only capture flow as the standalone app, launched instantly
/// from an App Clip Code / QR without a full install. Links CaptureKit only (no wallet code) to stay
/// under the App Clip size budget — see docs/nfc-pid/appclip-size-feasibility.md.
@main
struct PIDCaptureClipApp: App {
    @State private var invocationURL: URL?

    var body: some Scene {
        WindowGroup {
            Group {
                if let url = invocationURL {
                    CaptureFlowView(invocationURL: url)
                } else {
                    ClipWaitingView()
                }
            }
            .onOpenURL { invocationURL = $0 }
            .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
                if let url = activity.webpageURL { invocationURL = url }
            }
        }
    }
}

struct ClipWaitingView: View {
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "wallet.pass")
                .font(.system(size: 56))
                .foregroundStyle(.secondary)
            Text("Preparing your passport capture…")
                .foregroundStyle(.secondary)
        }
        .padding()
    }
}
