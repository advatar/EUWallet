import XCTest
@testable import WalletShell

final class ConsumerCopyTests: XCTestCase {
    func testKnownProtocolClaimsHavePlainLanguageLabels() {
        XCTAssertEqual(ConsumerCopy.claimName("org.iso.18013.5.1.portrait"), "Portrait")
        XCTAssertEqual(ConsumerCopy.claimName("age_over_18"), "Over 18")
        XCTAssertEqual(ConsumerCopy.claimName("birth_date"), "Date of birth")
        XCTAssertEqual(
            ConsumerCopy.claimName("org.iso.18013.5.1.age_over_18 [retained]"),
            "Over 18 (kept by requester)")
    }

    func testUnknownClaimsAreReadableWithoutChangingTheirValue() {
        XCTAssertEqual(ConsumerCopy.claimName("issuing_authority"), "Issuing Authority")
    }

    func testActivityAndOutcomeAvoidProtocolTerminology() {
        XCTAssertEqual(ConsumerCopy.activityName("presentation"), "Information shared")
        XCTAssertEqual(ConsumerCopy.outcomeName("declined"), "Not approved")
    }
}
