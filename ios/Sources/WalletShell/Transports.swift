import Foundation

/// Proximity transports are thin adapters: they move opaque bytes to/from the core's
/// iso18013-5 machine and contain NO protocol logic (plan Section 5/8).
public protocol ProximityTransport {
    func send(_ bytes: Data) async throws
    func receive() async throws -> Data
}

#if canImport(CoreBluetooth)
@preconcurrency import CoreBluetooth

/// ISO/IEC 18013-5 mdoc BLE GATT profile (§8.3.3.1.1). The *service* UUID is ephemeral — it is
/// carried inside the `DeviceEngagement` the reader scanned, so it changes every session — but the
/// four characteristic UUIDs are fixed by the standard. All live under the base UUID
/// `0000XXXX-A123-48CE-896B-4C76973373E6`. Exposed as computed properties because `CBUUID` is a
/// non-`Sendable` reference type (Swift 6 forbids it as shared mutable global state).
public enum MdocBleProfile {
    /// State: the reader writes `stateStart` to begin and `stateEnd` to finish; the mdoc may notify.
    public static var state: CBUUID { CBUUID(string: "00000005-A123-48CE-896B-4C76973373E6") }
    /// Client2Server: reader → mdoc. The reader writes the (encrypted) request here, chunked.
    public static var client2Server: CBUUID { CBUUID(string: "00000006-A123-48CE-896B-4C76973373E6") }
    /// Server2Client: mdoc → reader. The mdoc notifies the (encrypted) response here, chunked.
    public static var server2Client: CBUUID { CBUUID(string: "00000007-A123-48CE-896B-4C76973373E6") }
    /// Ident: the reader reads this to confirm it connected to the intended mdoc before sending.
    public static var ident: CBUUID { CBUUID(string: "00000008-A123-48CE-896B-4C76973373E6") }

    /// State byte: transaction start.
    public static let stateStart: UInt8 = 0x01
    /// State byte: transaction end.
    public static let stateEnd: UInt8 = 0x02
}

/// Pure message framing for the mdoc BLE profile (§8.3.3.1.1.5): each GATT packet is one chunk,
/// prefixed with a single status byte — `0x01` = "more chunks follow", `0x00` = "this is the last".
/// Isolated as pure functions so the split/reassembly is unit-testable without a radio.
public enum BleMessageFraming {
    static let more: UInt8 = 0x01
    static let last: UInt8 = 0x00

    /// Split `payload` into GATT chunks, each ≤ `maxChunk` bytes *including* the 1-byte status prefix.
    /// `maxChunk` is the negotiated ATT payload (`maximumUpdateValueLength`); we never emit an empty
    /// body, and an empty payload still produces one final (empty-body) chunk.
    public static func split(_ payload: Data, maxChunk: Int) -> [Data] {
        let body = max(1, maxChunk - 1)
        guard !payload.isEmpty else { return [Data([last])] }
        var chunks: [Data] = []
        var offset = 0
        while offset < payload.count {
            let end = min(offset + body, payload.count)
            let isLast = end == payload.count
            var chunk = Data([isLast ? last : more])
            chunk.append(payload.subdata(in: offset..<end))
            chunks.append(chunk)
            offset = end
        }
        return chunks
    }

    /// Whether this chunk is the final one of a message.
    public static func isLast(_ chunk: Data) -> Bool {
        chunk.first == last
    }

    /// The body of a chunk (everything after the status prefix).
    public static func body(_ chunk: Data) -> Data {
        chunk.isEmpty ? Data() : chunk.subdata(in: 1..<chunk.count)
    }
}

/// BLE transport for ISO/IEC 18013-5 in-person presentation, **mdoc peripheral-server mode**: the
/// wallet is the GATT *peripheral*, the reader is the *central*. It advertises the ephemeral service
/// UUID from the DeviceEngagement, serves the four profile characteristics, reassembles the reader's
/// chunked request off `Client2Server`, and streams the device response back as chunked notifications
/// on `Server2Client`.
///
/// This is a pure byte pipe: it holds NO 18013-5 protocol logic (the sans-IO core owns that). The
/// `SessionData` encryption (HKDF-derived AES-256-GCM) sits *above* this transport and is a tracked
/// follow-up; here we move opaque frames. Delegate callbacks all run on `bleQueue`, and every piece
/// of mutable state is touched only there — hence `@unchecked Sendable`.
public final class BleTransport: NSObject, ProximityTransport, @unchecked Sendable {
    private let serviceUUID: CBUUID
    private let ident: Data
    private let bleQueue = DispatchQueue(label: "eu.advatar.wallet.ble")

    private var manager: CBPeripheralManager!
    private var server2ClientChar: CBMutableCharacteristic?
    private var subscribedCentral: CBCentral?

    // Inbound (reader → mdoc) reassembly.
    private var inboundBuffer = Data()
    private var completedInbound: [Data] = []
    private var receiveContinuation: CheckedContinuation<Data, Error>?

    // Outbound (mdoc → reader) chunk pump.
    private var outboundChunks: [Data] = []
    private var sendContinuation: CheckedContinuation<Void, Error>?

    private var started = false

    /// - Parameters:
    ///   - serviceUUID: the ephemeral BLE service UUID embedded in the emitted DeviceEngagement.
    ///   - ident: the value the reader reads from the Ident characteristic to confirm the device
    ///     (per §8.3.3.1.1.4 this is `HKDF(EDeviceKeyBytes, "BLEIdent")` truncated to 16 bytes,
    ///     computed by the caller).
    public init(serviceUUID: CBUUID, ident: Data) {
        self.serviceUUID = serviceUUID
        self.ident = ident
        super.init()
    }

    /// Convenience: build from the 16-byte UUID bytes carried in the DeviceEngagement CBOR.
    public convenience init?(uuidBytes: Data, ident: Data) {
        guard uuidBytes.count == 16 else { return nil }
        let hex = uuidBytes.map { String(format: "%02x", $0) }.joined()
        let dashed =
            "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-"
            + "\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20))"
        self.init(serviceUUID: CBUUID(string: dashed), ident: ident)
    }

    /// Power on the peripheral, register the mdoc service, and begin advertising.
    public func start() {
        bleQueue.async {
            guard !self.started else { return }
            self.started = true
            self.manager = CBPeripheralManager(delegate: self, queue: self.bleQueue)
        }
    }

    /// Stop advertising and tear down (idempotent).
    public func stop() {
        bleQueue.async {
            guard self.started else { return }
            self.started = false
            self.manager?.stopAdvertising()
            self.manager?.removeAllServices()
            self.failPending(TransportError.closed)
        }
    }

    // MARK: ProximityTransport

    public func send(_ bytes: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            bleQueue.async {
                guard let s2c = self.server2ClientChar, self.subscribedCentral != nil else {
                    cont.resume(throwing: TransportError.notConnected)
                    return
                }
                let mtu = self.subscribedCentral?.maximumUpdateValueLength ?? 20
                self.outboundChunks = BleMessageFraming.split(bytes, maxChunk: mtu)
                self.sendContinuation = cont
                self.pumpOutbound(char: s2c)
            }
        }
    }

    public func receive() async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            bleQueue.async {
                if !self.completedInbound.isEmpty {
                    cont.resume(returning: self.completedInbound.removeFirst())
                } else if self.receiveContinuation != nil {
                    cont.resume(throwing: TransportError.receiveBusy)
                } else {
                    self.receiveContinuation = cont
                }
            }
        }
    }

    // MARK: internals (bleQueue only)

    private func pumpOutbound(char: CBMutableCharacteristic) {
        while let chunk = outboundChunks.first {
            let ok = manager.updateValue(chunk, for: char, onSubscribedCentrals: nil)
            if ok {
                outboundChunks.removeFirst()
            } else {
                return  // queue full — resume in peripheralManagerIsReady(toUpdateSubscribers:)
            }
        }
        sendContinuation?.resume()
        sendContinuation = nil
    }

    private func failPending(_ error: Error) {
        receiveContinuation?.resume(throwing: error)
        receiveContinuation = nil
        sendContinuation?.resume(throwing: error)
        sendContinuation = nil
        outboundChunks.removeAll()
    }

    public enum TransportError: Error {
        case notConnected
        case receiveBusy
        case closed
    }
}

extension BleTransport: CBPeripheralManagerDelegate {
    public func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        guard peripheral.state == .poweredOn else {
            failPending(TransportError.notConnected)
            return
        }
        let s2c = CBMutableCharacteristic(
            type: MdocBleProfile.server2Client, properties: [.notify], value: nil,
            permissions: [])
        let c2s = CBMutableCharacteristic(
            type: MdocBleProfile.client2Server,
            properties: [.write, .writeWithoutResponse], value: nil, permissions: [.writeable])
        let stateChar = CBMutableCharacteristic(
            type: MdocBleProfile.state,
            properties: [.notify, .write, .writeWithoutResponse], value: nil,
            permissions: [.writeable])
        let identChar = CBMutableCharacteristic(
            type: MdocBleProfile.ident, properties: [.read], value: ident, permissions: [.readable])
        server2ClientChar = s2c

        let service = CBMutableService(type: serviceUUID, primary: true)
        service.characteristics = [stateChar, c2s, s2c, identChar]
        peripheral.add(service)
        peripheral.startAdvertising([CBAdvertisementDataServiceUUIDsKey: [serviceUUID]])
    }

    public func peripheralManager(
        _ peripheral: CBPeripheralManager, central: CBCentral,
        didSubscribeTo characteristic: CBCharacteristic
    ) {
        if characteristic.uuid == MdocBleProfile.server2Client {
            subscribedCentral = central
        }
    }

    public func peripheralManager(
        _ peripheral: CBPeripheralManager, central: CBCentral,
        didUnsubscribeFrom characteristic: CBCharacteristic
    ) {
        if characteristic.uuid == MdocBleProfile.server2Client {
            subscribedCentral = nil
        }
    }

    public func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        if let s2c = server2ClientChar {
            pumpOutbound(char: s2c)
        }
    }

    public func peripheralManager(
        _ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]
    ) {
        for request in requests {
            guard let value = request.value else { continue }
            switch request.characteristic.uuid {
            case MdocBleProfile.client2Server:
                ingestInbound(value)
            case MdocBleProfile.state:
                // start (0x01) begins a fresh message; end (0x02) tears the pipe down.
                if value.first == MdocBleProfile.stateEnd {
                    failPending(TransportError.closed)
                } else if value.first == MdocBleProfile.stateStart {
                    inboundBuffer.removeAll(keepingCapacity: true)
                }
            default:
                break
            }
        }
        // The first request carries the response type for the whole batch.
        if let first = requests.first {
            peripheral.respond(to: first, withResult: .success)
        }
    }

    private func ingestInbound(_ chunk: Data) {
        inboundBuffer.append(BleMessageFraming.body(chunk))
        guard BleMessageFraming.isLast(chunk) else { return }
        let message = inboundBuffer
        inboundBuffer = Data()
        if let cont = receiveContinuation {
            receiveContinuation = nil
            cont.resume(returning: message)
        } else {
            completedInbound.append(message)
        }
    }
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
