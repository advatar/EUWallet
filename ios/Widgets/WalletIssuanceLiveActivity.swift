import ActivityKit
import SwiftUI
import WidgetKit

/// Lock Screen banner + Dynamic Island presentation for the "Adding your document" Live Activity.
///
/// Renders only the non-sensitive attributes carried by `WalletIssuanceAttributes` — the document
/// type name and a coarse progress stage. Never any credential contents.
struct WalletIssuanceLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: WalletIssuanceAttributes.self) { context in
            lockScreen(context)
                .activityBackgroundTint(.black.opacity(0.35))
                .activitySystemActionForegroundColor(.white)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Image(systemName: context.attributes.systemImage)
                        .font(.title2)
                        .foregroundStyle(.tint)
                        .padding(.leading, 4)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    Image(systemName: context.state.systemImage)
                        .font(.title3)
                        .foregroundStyle(tint(for: context.state.stage))
                        .padding(.trailing, 4)
                }
                DynamicIslandExpandedRegion(.center) {
                    VStack(spacing: 2) {
                        Text(context.attributes.documentName)
                            .font(.headline)
                            .lineLimit(1)
                        Text(context.state.title)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                DynamicIslandExpandedRegion(.bottom) {
                    ProgressView(value: context.state.fraction)
                        .tint(tint(for: context.state.stage))
                }
            } compactLeading: {
                Image(systemName: context.attributes.systemImage)
                    .foregroundStyle(.tint)
            } compactTrailing: {
                Image(systemName: context.state.systemImage)
                    .foregroundStyle(tint(for: context.state.stage))
            } minimal: {
                Image(systemName: context.state.systemImage)
                    .foregroundStyle(tint(for: context.state.stage))
            }
            .widgetURL(WalletDeepLink.present.url)
        }
    }

    @ViewBuilder
    private func lockScreen(
        _ context: ActivityViewContext<WalletIssuanceAttributes>
    ) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: context.attributes.systemImage)
                    .font(.title2)
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Adding \(context.attributes.documentName)")
                        .font(.headline)
                        .lineLimit(1)
                    Text(context.state.title)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                Image(systemName: context.state.systemImage)
                    .font(.title3)
                    .foregroundStyle(tint(for: context.state.stage))
            }
            ProgressView(value: context.state.fraction)
                .tint(tint(for: context.state.stage))
        }
        .padding()
    }

    private func tint(
        for stage: WalletIssuanceAttributes.ContentState.Stage
    ) -> Color {
        switch stage {
        case .done: return .green
        case .failed: return .orange
        default: return .accentColor
        }
    }
}
