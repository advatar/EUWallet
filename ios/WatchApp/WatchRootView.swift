import SwiftUI

/// The EU Wallet Apple Watch glance: how many documents the wallet holds on the paired iPhone.
///
/// A pure glance — the watch shows a COUNT only, never any document contents (the sensitive material
/// stays on the phone behind its consent screens), and it has no actions of its own: the watch can't
/// scan a QR code (no scanning camera) or present a credential, so there is nothing meaningful for it
/// to do beyond mirroring status. All wallet flows happen on the phone.
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

                if !client.reachable {
                    Section {
                        Label("Open EU Wallet on your iPhone to sync", systemImage: "iphone")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("EU Wallet")
        }
    }
}
