import Foundation

/// Proximity transports are thin adapters: they move opaque bytes to/from the core's
/// iso18013-5 machine and contain NO protocol logic (plan Section 5/8).
public protocol ProximityTransport {
    func send(_ bytes: Data) async throws
    func receive() async throws -> Data
}

#if canImport(CoreBluetooth)
import CoreBluetooth
/// BLE transport (ISO 18013-5 mdoc proximity). Skeleton — wire up peripheral/central per plan.
public final class BleTransport: NSObject, ProximityTransport {
    public func send(_ bytes: Data) async throws { /* GATT write */ }
    public func receive() async throws -> Data { Data() }
}
#endif

#if canImport(CoreNFC)
import CoreNFC
/// NFC engagement (iOS only). Guarded so the package still builds on macOS.
public final class NfcEngagement { public init() {} }
#endif

/// QR device-engagement helpers (present a QR / scan a QR). Uses Vision/AVFoundation in-app.
public enum QrEngagement {
    public static func encodePayload(_ bytes: Data) -> String { bytes.base64EncodedString() }
    public static func decodePayload(_ text: String) -> Data? { Data(base64Encoded: text) }
}
