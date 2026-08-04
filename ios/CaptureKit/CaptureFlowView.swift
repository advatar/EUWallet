import SwiftUI

/// The whole companion UI: launched with an invocation URL, it captures the MRZ (camera or manual),
/// then runs the capture coordinator (liveness → chip → submit) and reports the outcome. Shared by
/// the standalone PIDCapture app and the PIDCaptureClip App Clip.
public struct CaptureFlowView: View {
    /// Default `service-nfc` relay for eMRTD reads (overridable).
    public static let defaultNFCServerURL = "wss://nfc.dev-eu.iproov.id/channel"

    private let invocationURL: URL
    private let nfcServerURL: String

    @StateObject private var model: CaptureFlowModel

    public init(invocationURL: URL, nfcServerURL: String = CaptureFlowView.defaultNFCServerURL) {
        self.invocationURL = invocationURL
        self.nfcServerURL = nfcServerURL
        _model = StateObject(
            wrappedValue: CaptureFlowModel(invocationURL: invocationURL, nfcServerURL: nfcServerURL))
    }

    public var body: some View {
        VStack(spacing: 24) {
            Text("Add PID from passport")
                .font(.title2).bold()

            switch model.phase {
            case .needsMRZ:
                VStack(spacing: 16) {
                    Text("Scan the machine-readable zone on your passport data page.")
                        .multilineTextAlignment(.center)
                        .foregroundStyle(.secondary)
                    MRZScanner { mrz in model.start(mrz: .raw(mrz)) }
                        .frame(height: 260)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                }
            case .running:
                VStack(spacing: 12) {
                    ProgressView()
                    Text(model.stageText).foregroundStyle(.secondary)
                }
            case .issued:
                Label("PID issued to the target wallet", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green).font(.headline)
            case let .failed(message):
                VStack(spacing: 12) {
                    Label("Capture failed", systemImage: "xmark.octagon.fill")
                        .foregroundStyle(.red).font(.headline)
                    Text(message).font(.footnote).foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    Button("Try again") { model.reset() }
                }
            case .invalidLink:
                Label("This link is missing a capture session.", systemImage: "link.badge.plus")
                    .foregroundStyle(.red)
            }
        }
        .padding()
    }
}

/// View model driving one capture. `@MainActor` so UI mutation is on the main thread.
@MainActor
final class CaptureFlowModel: ObservableObject {
    enum Phase: Equatable {
        case needsMRZ
        case running
        case issued
        case failed(String)
        case invalidLink
    }

    @Published private(set) var phase: Phase
    @Published private(set) var stageText = ""

    private let sessionID: String?
    private let coordinator: CaptureCoordinator?

    init(invocationURL: URL, nfcServerURL: String) {
        // The QR lives on the issuer domain, so the issuer base URL is the invocation URL's origin.
        if let sessionID = CaptureSessionClient.sessionID(fromInvocation: invocationURL),
            let scheme = invocationURL.scheme,
            let host = invocationURL.host
        {
            var base = "\(scheme)://\(host)"
            if let port = invocationURL.port { base += ":\(port)" }
            let client = CaptureSessionClient(issuerBaseURL: URL(string: base)!)
            self.sessionID = sessionID
            coordinator = CaptureCoordinator(client: client, nfcServerURL: nfcServerURL)
            phase = .needsMRZ
        } else {
            sessionID = nil
            coordinator = nil
            phase = .invalidLink
        }
    }

    func start(mrz: MRZInput) {
        guard let sessionID, let coordinator else { return }
        phase = .running
        Task {
            let result = await coordinator.run(sessionID: sessionID, mrz: mrz) { stage in
                Task { @MainActor in self.apply(stage) }
            }
            if result?.status != .issued, case .running = self.phase {
                self.phase = .failed("The issuer did not complete issuance.")
            }
        }
    }

    func reset() { phase = .needsMRZ }

    private func apply(_ stage: CaptureCoordinator.Stage) {
        switch stage {
        case .fetchingSession: stageText = "Preparing session…"
        case .capturingLiveness: stageText = "Face verification…"
        case .readingChip: stageText = "Reading passport chip…"
        case .submitting: stageText = "Sending to issuer…"
        case .issued: phase = .issued
        case let .failed(message): phase = .failed(message)
        }
    }
}
