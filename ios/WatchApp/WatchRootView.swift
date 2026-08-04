import SwiftUI

/// The EU Wallet Apple Watch glance: how many documents the wallet holds on the paired iPhone, and
/// two quick actions that nudge the phone to scan a code or share a document.
///
/// The watch shows a COUNT only, never any document contents — the sensitive material stays on the
/// phone behind its consent screens.
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

                Section("On your iPhone") {
                    Button {
                        client.request(.scan)
                    } label: {
                        Label("Scan a code", systemImage: "qrcode.viewfinder")
                    }
                    Button {
                        client.request(.present)
                    } label: {
                        Label("Share a document", systemImage: "person.text.rectangle")
                    }
                }

                if !client.reachable {
                    Section {
                        Label("Open EU Wallet on iPhone to sync", systemImage: "iphone")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("EU Wallet")
        }
    }
}
