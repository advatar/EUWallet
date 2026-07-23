#if canImport(SwiftUI)
import XCTest
@testable import WalletShell

final class ConsumerDesignTests: XCTestCase {
    func testConsumerActionsMeetAccessibleTargetAndPrototypeMetrics() {
        XCTAssertGreaterThanOrEqual(
            ConsumerDesign.minimumTouchTarget,
            44,
            "every interactive target must satisfy the 44-point accessibility floor")
        XCTAssertGreaterThanOrEqual(
            ConsumerDesign.primaryActionHeight,
            ConsumerDesign.minimumTouchTarget,
            "full-width primary actions must remain easier to acquire than the minimum")
        XCTAssertEqual(ConsumerDesign.actionCornerRadius, 14)
        XCTAssertEqual(ConsumerDesign.surfaceCornerRadius, 16)
    }

    func testIssuanceStartsOnlyFromAReceivedCredentialOffer() {
        XCTAssertFalse(ConsumerIssuanceEntryPolicy.supportsArbitraryCredentialTypeSelection)
        XCTAssertEqual(
            ConsumerIssuanceEntryPolicy.supportedModes,
            [.qrCode, .verifiedLink])
        XCTAssertEqual(ConsumerIssuanceEntryPolicy.addActionTitle, "Scan a QR code")
    }
}
#endif
