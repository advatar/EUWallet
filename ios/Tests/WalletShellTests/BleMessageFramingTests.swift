import XCTest

@testable import WalletShell

#if canImport(CoreBluetooth)

/// Pure-function coverage of the ISO/IEC 18013-5 mdoc BLE chunk framing (status-prefixed GATT
/// packets). The radio itself needs a second device, but split→reassemble is deterministic and is
/// asserted here end-to-end.
final class BleMessageFramingTests: XCTestCase {
    /// Reassemble the way the peripheral does: concat every chunk body, stop at the last chunk.
    private func reassemble(_ chunks: [Data]) -> Data {
        var out = Data()
        for chunk in chunks {
            out.append(BleMessageFraming.body(chunk))
            if BleMessageFraming.isLast(chunk) { break }
        }
        return out
    }

    func testSplitReassembleRoundTrips() {
        for length in [0, 1, 19, 20, 21, 100, 512, 1024] {
            let payload = Data((0..<length).map { UInt8($0 & 0xFF) })
            let chunks = BleMessageFraming.split(payload, maxChunk: 20)
            XCTAssertEqual(reassemble(chunks), payload, "round-trip at length \(length)")
        }
    }

    func testEveryChunkFitsTheMtuAndCarriesAPrefix() {
        let payload = Data(repeating: 0xAB, count: 137)
        let mtu = 23
        let chunks = BleMessageFraming.split(payload, maxChunk: mtu)
        for chunk in chunks {
            XCTAssertGreaterThanOrEqual(chunk.count, 1, "every chunk has a status prefix")
            XCTAssertLessThanOrEqual(chunk.count, mtu, "no chunk exceeds the negotiated MTU")
        }
        // Exactly one final chunk, and it is the last element.
        let lastFlags = chunks.map { BleMessageFraming.isLast($0) }
        XCTAssertEqual(lastFlags.filter { $0 }.count, 1)
        XCTAssertTrue(lastFlags.last == true)
    }

    func testEmptyPayloadStillProducesOneFinalChunk() {
        let chunks = BleMessageFraming.split(Data(), maxChunk: 20)
        XCTAssertEqual(chunks.count, 1)
        XCTAssertTrue(BleMessageFraming.isLast(chunks[0]))
        XCTAssertTrue(BleMessageFraming.body(chunks[0]).isEmpty)
    }
}

#endif
