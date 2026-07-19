import XCTest
@testable import WalletShell

/// Tests the DER→JOSE ECDSA signature conversion in isolation. JOSE ES256 (what the Rust core
/// verifies) is fixed-width `r‖s` (64 bytes); the Secure Enclave emits DER. Getting the
/// leading-sign-zero strip and short-integer left-pad right is what makes enclave signatures
/// verify against the core.
final class SecureEnclaveSignerTests: XCTestCase {
    private func der(r: [UInt8], s: [UInt8]) -> Data {
        func intTLV(_ v: [UInt8]) -> [UInt8] { [0x02, UInt8(v.count)] + v }
        let content = intTLV(r) + intTLV(s)
        return Data([0x30, UInt8(content.count)] + content)
    }

    func testPlain32ByteIntegers() {
        let r = [UInt8](repeating: 0x11, count: 32) // 0x11 high bit clear → no sign prefix
        let s = [UInt8](repeating: 0x22, count: 32)
        let raw = SecureEnclaveSigner.joseSignature(fromDER: der(r: r, s: s))
        XCTAssertEqual(raw, Data(r + s))
        XCTAssertEqual(raw?.count, 64)
    }

    func testStripsDerLeadingSignZero() {
        // s has its top bit set, so DER prepends 0x00 (33-byte INTEGER); output must be 32 bytes.
        let r = [UInt8](repeating: 0x11, count: 32)
        let sValue = [UInt8](repeating: 0xBB, count: 32) // 0xBB top bit set
        let sDer = [0x00] + sValue
        let raw = SecureEnclaveSigner.joseSignature(fromDER: der(r: r, s: sDer))
        XCTAssertEqual(raw?.count, 64)
        XCTAssertEqual(raw, Data(r + sValue), "the sign zero is stripped, leaving the true s")
    }

    func testLeftPadsShortInteger() {
        // A 30-byte r (value happened to have leading zeros) must be left-padded back to 32.
        let rShort = [UInt8](repeating: 0x33, count: 30)
        let s = [UInt8](repeating: 0x44, count: 32)
        let raw = SecureEnclaveSigner.joseSignature(fromDER: der(r: rShort, s: s))
        XCTAssertEqual(raw?.count, 64)
        XCTAssertEqual(Array(raw!.prefix(32)), [0x00, 0x00] + rShort)
    }

    func testRejectsNonSequence() {
        XCTAssertNil(SecureEnclaveSigner.joseSignature(fromDER: Data([0x02, 0x01, 0x00])))
    }
}
