import SwiftUI

/// The EU Wallet Apple Watch glance: how many documents the wallet holds on the paired iPhone, and
/// two "continue on iPhone" actions.
///
/// The watch shows a COUNT only, never any document contents — the sensitive material stays on the
/// phone behind its consent screens. It also CANNOT scan a QR code (no scanning camera on the watch)
/// or present a credential itself; the action buttons only ask the paired iPhone to open the right
/// flow, so their labels say "on iPhone" and the footer makes the hand-off explicit. The watch
/// cannot force the phone app to the foreground (an Apple platform restriction), so a requested
/// action is applied the next time the wallet is opened on the phone.
struct WatchRootView: View {
    @StateObject private var client = WatchConnectivityClient()

    private var noun: String { client.documentCount == 1 ? "document" : "documents" }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack(spacing: 12) {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.title2)
                            .foregroundStyle(.tint)
                        VStack(alignment: .leading, spacing: 1) {
                            Text("\(client.documentCount)")
                                .font(.system(.title2, design: .rounded).bold())
                            Text(client.documentCount == 0 ? "No documents yet" : "\(noun) on iPhone")
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 2)
                }

                Section {
                    Button {
                        client.request(.scan)
                    } label: {
                        Label("Scan on iPhone", systemImage: "qrcode.viewfinder")
                    }
                    Button {
                        client.request(.present)
                    } label: {
                        Label("Share on iPhone", systemImage: "person.text.rectangle")
                    }
                } header: {
                    Text("Continue on iPhone")
                } footer: {
                    Text(client.reachable
                        ? "Opens the wallet on your iPhone — the watch can’t scan or show documents itself."
                        : "Open EU Wallet on your iPhone, then try again.")
                    .font(.caption2)
                }
            }
            .navigationTitle("EU Wallet")
        }
    }
}
