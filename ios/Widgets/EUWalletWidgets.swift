import AppIntents
import SwiftUI
import WidgetKit

// MARK: - Timeline

struct WalletStatusEntry: TimelineEntry {
    let date: Date
    let documentCount: Int
}

struct WalletStatusProvider: TimelineProvider {
    func placeholder(in _: Context) -> WalletStatusEntry {
        WalletStatusEntry(date: .now, documentCount: 3)
    }

    func getSnapshot(in _: Context, completion: @escaping (WalletStatusEntry) -> Void) {
        completion(WalletStatusEntry(date: .now, documentCount: WalletStatusStore.documentCount()))
    }

    func getTimeline(in _: Context, completion: @escaping (Timeline<WalletStatusEntry>) -> Void) {
        // The app reloads timelines on every holdings change, so a single non-expiring entry is enough.
        let entry = WalletStatusEntry(date: .now, documentCount: WalletStatusStore.documentCount())
        completion(Timeline(entries: [entry], policy: .never))
    }
}

// MARK: - Views (status only — never any credential data)

struct WalletStatusWidgetView: View {
    @Environment(\.widgetFamily) private var family
    let entry: WalletStatusEntry

    private var countText: String { "\(entry.documentCount)" }
    private var noun: String { entry.documentCount == 1 ? "document" : "documents" }

    var body: some View {
        content
            .widgetURL(WalletDeepLink.present.url)
            .containerBackground(.fill.tertiary, for: .widget)
    }

    @ViewBuilder private var content: some View {
        switch family {
        case .accessoryInline:
            Label("\(countText) \(noun)", systemImage: "wallet.pass")
        case .accessoryCircular:
            ZStack {
                AccessoryWidgetBackground()
                VStack(spacing: 0) {
                    Image(systemName: "wallet.pass").font(.caption2)
                    Text(countText).font(.headline.bold())
                }
            }
        case .accessoryRectangular:
            HStack(spacing: 8) {
                Image(systemName: "checkmark.shield.fill").font(.title3)
                VStack(alignment: .leading) {
                    Text("EU Wallet").font(.headline)
                    Text("\(countText) \(noun) · tap to share").font(.caption)
                }
            }
        default:
            VStack(alignment: .leading, spacing: 6) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.title2)
                    .foregroundStyle(.tint)
                Spacer(minLength: 0)
                Text(countText)
                    .font(.system(size: 40, weight: .bold, design: .rounded))
                Text(entry.documentCount == 0 ? "No documents yet" : "\(noun) on this iPhone")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(entry.documentCount == 0 ? "Tap to add" : "Tap to share")
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.tint)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct WalletStatusWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(
            kind: "eu.advatar.wallet.widget.status",
            provider: WalletStatusProvider()
        ) { entry in
            WalletStatusWidgetView(entry: entry)
        }
        .configurationDisplayName("EU Wallet")
        .description("See how many documents you hold and open the wallet quickly.")
        .supportedFamilies([
            .systemSmall, .systemMedium,
            .accessoryCircular, .accessoryRectangular, .accessoryInline,
        ])
    }
}

// MARK: - Control Center controls (iOS 18+)

@available(iOS 18.0, *)
struct WalletScanControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: "eu.advatar.wallet.control.scan") {
            ControlWidgetButton(action: ScanIntent()) {
                Label("Scan", systemImage: "qrcode.viewfinder")
            }
        }
        .displayName("EU Wallet: Scan")
        .description("Scan a QR code with the EU Wallet.")
    }
}

@available(iOS 18.0, *)
struct WalletPassportControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: "eu.advatar.wallet.control.passport") {
            ControlWidgetButton(action: AddFromPassportIntent()) {
                Label("Add ID", systemImage: "wave.3.right.circle")
            }
        }
        .displayName("EU Wallet: Add from passport")
        .description("Add a PID by reading a passport chip.")
    }
}

// MARK: - Bundle

@main
struct EUWalletWidgetBundle: WidgetBundle {
    var body: some Widget {
        WalletStatusWidget()
        if #available(iOS 18.0, *) {
            WalletScanControl()
            WalletPassportControl()
        }
    }
}
