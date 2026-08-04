import AVFoundation
import SwiftUI
import Vision

/// Live camera scanner for the machine-readable zone (MRZ) on a passport/ID data page. Uses Vision
/// text recognition; when it sees a complete ICAO 9303 block (TD3 2×44, TD2 2×36, or TD1 3×30) it
/// emits the raw MRZ (newline-joined) once and stops. The raw MRZ goes straight to the reader, which
/// derives the BAC/PACE key and O/0-corrects against the printed check digit.
struct MRZScannerView: UIViewControllerRepresentable {
    let onCapture: (String) -> Void

    func makeUIViewController(context _: Context) -> MRZScannerViewController {
        let controller = MRZScannerViewController()
        controller.onCapture = onCapture
        return controller
    }

    func updateUIViewController(_: MRZScannerViewController, context _: Context) {}
}

final class MRZScannerViewController: UIViewController, AVCaptureVideoDataOutputSampleBufferDelegate {
    var onCapture: ((String) -> Void)?

    private let session = AVCaptureSession()
    private let output = AVCaptureVideoDataOutput()
    private let queue = DispatchQueue(label: "eu.advatar.wallet.mrz-scan")
    private lazy var preview = AVCaptureVideoPreviewLayer(session: session)
    private var captured = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview.frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
            guard let self, granted else { return }
            self.queue.async {
                if self.session.inputs.isEmpty { self.configureSession() }
                if !self.session.isRunning { self.session.startRunning() }
            }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        queue.async { if self.session.isRunning { self.session.stopRunning() } }
    }

    private func configureSession() {
        session.beginConfiguration()
        session.sessionPreset = .hd1920x1080
        defer { session.commitConfiguration() }
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input)
        else { return }
        session.addInput(input)
        output.setSampleBufferDelegate(self, queue: queue)
        output.videoSettings = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
        ]
        if session.canAddOutput(output) { session.addOutput(output) }
    }

    func captureOutput(
        _: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer,
        from _: AVCaptureConnection
    ) {
        guard !captured, let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        let request = VNRecognizeTextRequest { [weak self] request, _ in
            guard let self, !self.captured else { return }
            let lines = (request.results as? [VNRecognizedTextObservation] ?? [])
                .compactMap { $0.topCandidates(1).first?.string }
            guard let mrz = MRZScannerViewController.extractMrz(from: lines) else { return }
            self.captured = true
            DispatchQueue.main.async { self.onCapture?(mrz) }
        }
        request.recognitionLevel = .accurate
        request.usesLanguageCorrection = false
        let handler = VNImageRequestHandler(cvPixelBuffer: pixelBuffer, orientation: .right)
        try? handler.perform([request])
    }

    /// Pull an ICAO 9303 MRZ block out of noisy OCR lines. Pure + unit-testable.
    static func extractMrz(from rawLines: [String]) -> String? {
        let allowed = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<")
        let candidates =
            rawLines
            .map { line in
                line.uppercased()
                    .replacingOccurrences(of: " ", with: "")
                    .replacingOccurrences(of: "«", with: "<<") // common OCR of the "<<" filler
                    .replacingOccurrences(of: "‹", with: "<")
                    .filter { allowed.contains($0) }
            }
            .filter { $0.contains("<") }

        func block(length: Int, count: Int) -> String? {
            let matches = candidates.filter { $0.count == length }
            guard matches.count >= count else { return nil }
            return matches.suffix(count).joined(separator: "\n")
        }
        // TD3 (passport) 2×44, TD2 2×36, TD1 3×30.
        return block(length: 44, count: 2)
            ?? block(length: 36, count: 2)
            ?? block(length: 30, count: 3)
    }
}
