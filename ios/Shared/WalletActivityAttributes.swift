import ActivityKit
import Foundation

/// Live Activity for an in-progress credential issuance ("Adding your document…"), shown on the
/// Lock Screen and in the Dynamic Island.
///
/// PRIVACY: the Lock Screen and Dynamic Island are visible to anyone holding the phone, so only the
/// document *type* name (e.g. "Digital ID") and a coarse progress stage ever cross this boundary —
/// never any credential contents, claim values, holder name, or issuer PII. This mirrors the same
/// non-sensitive-status-only rule the widgets follow (`WalletStatusStore`).
public struct WalletIssuanceAttributes: ActivityAttributes {
    /// The changing part of the activity: how far the issuance has progressed.
    public struct ContentState: Codable, Hashable {
        public enum Stage: String, Codable, Hashable {
            /// Contacting the issuer and verifying the offer in-core.
            case connecting
            /// Waiting for the holder to review and approve the offer.
            case reviewing
            /// Device signing the proof-of-possession and storing the issued credential.
            case finishing
            /// Credential added successfully (terminal).
            case done
            /// Issuance could not complete (terminal).
            case failed
        }

        public var stage: Stage

        public init(stage: Stage) { self.stage = stage }

        /// Short holder-facing line describing the current stage.
        public var title: String {
            switch stage {
            case .connecting: return "Preparing…"
            case .reviewing: return "Review to continue"
            case .finishing: return "Finishing up…"
            case .done: return "Added"
            case .failed: return "Couldn’t add"
            }
        }

        /// SF Symbol reflecting the stage (used in the Dynamic Island / Lock Screen).
        public var systemImage: String {
            switch stage {
            case .connecting: return "arrow.triangle.2.circlepath"
            case .reviewing: return "hand.raised.fill"
            case .finishing: return "lock.shield.fill"
            case .done: return "checkmark.circle.fill"
            case .failed: return "exclamationmark.triangle.fill"
            }
        }

        /// Coarse progress for a determinate bar (never implies exact timing).
        public var fraction: Double {
            switch stage {
            case .connecting: return 0.25
            case .reviewing: return 0.5
            case .finishing: return 0.85
            case .done: return 1.0
            case .failed: return 1.0
            }
        }

        public var isTerminal: Bool { stage == .done || stage == .failed }
    }

    /// The document type being added (non-sensitive display name, e.g. "Digital ID").
    public var documentName: String
    /// SF Symbol for that document type (mirrors the wallet card icon).
    public var systemImage: String

    public init(documentName: String, systemImage: String) {
        self.documentName = documentName
        self.systemImage = systemImage
    }
}
