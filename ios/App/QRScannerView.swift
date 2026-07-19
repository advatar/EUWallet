import SwiftUI

#if canImport(VisionKit)
import VisionKit

/// A live camera QR scanner (VisionKit `DataScannerViewController`). Emits the first QR payload it
/// recognises. Only available on real devices with a camera; use `isAvailable` to gate it and fall
/// back to paste entry on the Simulator.
@available(iOS 16.0, *)
struct QRScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    /// True only when the hardware + OS support scanning AND the camera is available/authorised.
    static var isAvailable: Bool {
        DataScannerViewController.isSupported && DataScannerViewController.isAvailable
    }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let vc = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isHighlightingEnabled: true)
        vc.delegate = context.coordinator
        return vc
    }

    func updateUIViewController(_ vc: DataScannerViewController, context: Context) {
        try? vc.startScanning()
    }

    func makeCoordinator() -> Coordinator { Coordinator(onScan: onScan) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onScan: (String) -> Void
        private var fired = false
        init(onScan: @escaping (String) -> Void) { self.onScan = onScan }

        func dataScanner(
            _ scanner: DataScannerViewController,
            didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            guard !fired else { return }
            for item in addedItems {
                if case let .barcode(barcode) = item, let payload = barcode.payloadStringValue {
                    fired = true
                    scanner.stopScanning()
                    onScan(payload)
                    return
                }
            }
        }
    }
}
#endif
