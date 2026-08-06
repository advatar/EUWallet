import CoreImage
import Foundation
import SwiftUI

// The WalletShell sources (ProximityResponder, BleTransport, MdocBleProfile, …) compile straight
// into the app module per project.yml, so there is no `import WalletShell` here.

#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(CoreBluetooth)
import CoreBluetooth
#endif
#if canImport(UIKit)
import UIKit
#endif

/// Owns the ISO/IEC 18013-5 BLE peripheral transport for one in-person presentation, bridging the
/// wallet-core executor's two fire-and-forget proximity effects to CoreBluetooth. Created on the
/// main actor by `WalletModel`; its `ProximityResponder` methods are invoked from the effect
/// executor's drain (`@unchecked Sendable` — the effects run serially and the transport confines
/// its own work to its private BLE queue).
final class ProximityCoordinator: ProximityResponder, @unchecked Sendable {
    private let uuidBytes: Data
    private let onEngagement: @MainActor (Data) -> Void
    private let onReaderEstablishment: @MainActor (Data) -> Void
    private var receiveTask: Task<Void, Never>?
    #if canImport(CoreBluetooth)
    private var transport: BleTransport?
    #endif

    init(
        uuidBytes: Data,
        onEngagement: @escaping @MainActor (Data) -> Void,
        onReaderEstablishment: @escaping @MainActor (Data) -> Void
    ) {
        self.uuidBytes = uuidBytes
        self.onEngagement = onEngagement
        self.onReaderEstablishment = onReaderEstablishment
    }

    func emitEngagement(_ engagement: Data) async throws {
        #if canImport(CoreBluetooth)
        guard let transport = BleTransport(uuidBytes: uuidBytes, ident: Self.ident(for: engagement))
        else {
            throw ProximityError.invalidEngagement
        }
        transport.start()
        self.transport = transport
        await onEngagement(engagement)
        // Await the reader's SessionEstablishment OFF the engine loop, then hand it back as a fresh
        // cascade — never nested inside this effect's execution.
        receiveTask = Task { [onReaderEstablishment] in
            guard let establishment = try? await transport.receive() else { return }
            await onReaderEstablishment(establishment)
        }
        #else
        throw ProximityError.unsupported
        #endif
    }

    func emitResponse(_ response: Data) async throws {
        #if canImport(CoreBluetooth)
        guard let transport else { throw ProximityError.notConnected }
        try await transport.send(response)
        #else
        throw ProximityError.unsupported
        #endif
    }

    func stop() {
        receiveTask?.cancel()
        receiveTask = nil
        #if canImport(CoreBluetooth)
        transport?.stop()
        transport = nil
        #endif
    }

    /// ISO 18013-5 §8.3.3.1.1.4 Ident = HKDF(EDeviceKeyBytes, "BLEIdent")[..16]. EDeviceKeyBytes is
    /// not surfaced to the shell yet (tracked alongside the DC-API / #66 work), so a deterministic
    /// 16-byte value derived from the engagement lets bring-up readers connect. NOT conformant until
    /// the real EDeviceKey-derived ident is wired.
    private static func ident(for engagement: Data) -> Data {
        #if canImport(CryptoKit)
        return Data(SHA256.hash(data: engagement).prefix(16))
        #else
        return engagement.prefix(16)
        #endif
    }

    enum ProximityError: Error { case invalidEngagement, notConnected, unsupported }
}

/// Shows the ISO 18013-5 DeviceEngagement as a QR code for a reader to scan, while the wallet
/// advertises + awaits the connection over BLE. Transitions away (to the ProximityConsent screen)
/// once the reader replies.
struct ProximityEngagementView: View {
    let engagement: Data
    let onCancel: () -> Void

    var body: some View {
        VStack(spacing: 20) {
            Text("Show this to the reader")
                .font(.largeTitle.bold())
                .multilineTextAlignment(.center)
                .accessibilityAddTraits(.isHeader)
            Text("Hold your phone near the reader and keep this screen open until it connects.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            #if canImport(UIKit)
            if let image = Self.qrImage(from: Self.qrPayload(engagement)) {
                Image(uiImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 260, maxHeight: 260)
                    .accessibilityLabel("Device engagement QR code")
            }
            #endif
            ProgressView("Waiting for the reader…").controlSize(.large)
            Button("Cancel", role: .cancel, action: onCancel).controlSize(.large)
        }
        .padding(24)
    }

    /// ISO 18013-5 §8.2.2.3 QR payload: `mdoc:` + unpadded base64url(DeviceEngagement).
    private static func qrPayload(_ engagement: Data) -> String {
        let b64url = engagement.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "mdoc:" + b64url
    }

    #if canImport(UIKit)
    private static func qrImage(from string: String) -> UIImage? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data(string.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        guard let cg = CIContext().createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cg)
    }
    #endif
}
