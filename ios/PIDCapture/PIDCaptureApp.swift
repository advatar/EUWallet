import CaptureKit
import SwiftUI

/// Standalone PID Capture companion: a reader-only app that reads the eMRTD chip + runs a liveness
/// capture and hands the evidence to VCIssuer, which issues a PID to a DIFFERENT wallet. Launched by
/// a universal link (the QR VCIssuer shows) carrying the capture session id. No size budget — this is
/// the guaranteed path; the App Clip (PIDCaptureClip) is the frictionless variant.
@main
struct PIDCaptureApp: App {
    @State private var invocationURL: URL?

    var body: some Scene {
        WindowGroup {
            Group {
                if let url = invocationURL {
                    CaptureFlowView(invocationURL: url)
                } else {
                    WaitingForLinkView()
                }
            }
            .onOpenURL { invocationURL = $0 }
            .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
                if let url = activity.webpageURL { invocationURL = url }
            }
        }
    }
}

struct WaitingForLinkView: View {
    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 56))
                .foregroundStyle(.secondary)
            Text("Scan the QR shown by the issuer to add a PID from your passport.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
        }
        .padding()
    }
}
