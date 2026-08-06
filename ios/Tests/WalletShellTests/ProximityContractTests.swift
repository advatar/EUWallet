import XCTest

@testable import WalletShell

/// The FFI contract additions for in-person (ISO 18013-5) proximity presentation: decoding the two
/// new effects and the ProximityConsent screen, and the decision→event routing. Radio + a real
/// reader are hardware-gated, but the wire contract is deterministic and asserted here.
final class ProximityContractTests: XCTestCase {
    func testDecodesProximityTransportEffects() throws {
        let json = """
            [{"type":"emitDeviceEngagement","engagement":[1,2,3]},\
            {"type":"emitDeviceResponse","response":[4,5,6,7]}]
            """
        let effects = try WalletEffect.decodeCoreOutput(json)
        guard case .emitDeviceEngagement(let engagement) = effects[0] else {
            return XCTFail("expected emitDeviceEngagement")
        }
        XCTAssertEqual(engagement, [1, 2, 3])
        guard case .emitDeviceResponse(let response) = effects[1] else {
            return XCTFail("expected emitDeviceResponse")
        }
        XCTAssertEqual(response, [4, 5, 6, 7])
    }

    func testDecodesProximityConsentScreen() throws {
        let json = #"{"screen":"proximityConsent","requestedClaims":["org.iso.18013.5.1/age_over_18"]}"#
        let screen = try JSONDecoder().decode(ScreenDescription.self, from: Data(json.utf8))
        guard case .proximityConsent(let claims) = screen else {
            return XCTFail("expected proximityConsent")
        }
        XCTAssertEqual(claims, ["org.iso.18013.5.1/age_over_18"])
        // It routes to the proximity decision, whose approve/decline reuse userConsented/userDeclined.
        XCTAssertEqual(WalletDecisionKind(screen: screen), .proximity)
    }

    func testProximityConsentRenderCarriesOperationIdAndHash() throws {
        // The core registers a ProximityDecision op, so the render carries operationId + 32-byte hash.
        let hash = Array(repeating: UInt8(7), count: 32)
        let json = """
            [{"type":"render","operationId":9,"authorizationHash":\(hash),\
            "screen":{"screen":"proximityConsent","requestedClaims":["a/b"]}}]
            """
        let effects = try WalletEffect.decodeCoreOutput(json)
        guard case .render(let operationId, let authorizationHash, let screen) = effects[0] else {
            return XCTFail("expected render")
        }
        XCTAssertEqual(operationId, 9)
        XCTAssertEqual(authorizationHash?.count, 32)
        guard case .proximityConsent = screen else { return XCTFail("expected proximityConsent") }
    }

    func testProximityDecisionEmitsPlainConsentEvents() {
        let hash = Data(repeating: 7, count: 32)
        let approve = WalletDecisionKind.proximity.approvalEvent(operationId: 9, authorizationHash: hash)
        XCTAssertTrue(approve.contains(#""type":"userConsented""#))
        XCTAssertTrue(approve.contains(#""operationId":9"#))
        let decline = WalletDecisionKind.proximity.declineEvent(operationId: 9)
        XCTAssertTrue(decline.contains(#""type":"userDeclined""#))
    }

    func testProximityEventBuilders() {
        XCTAssertTrue(
            WalletEventJSON.proximityEngagementRequested(bleUuid: Data([1, 2, 3]))
                .contains(#""type":"proximityEngagementRequested""#))
        XCTAssertTrue(
            WalletEventJSON.proximityReaderEstablishment(sessionEstablishment: Data([9]))
                .contains(#""type":"proximityReaderEstablishment""#))
        XCTAssertEqual(
            WalletEventJSON.proximityReaderTermination(),
            #"{"type":"proximityReaderTermination"}"#)
    }
}
