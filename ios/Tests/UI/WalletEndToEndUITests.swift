import XCTest

/// End-to-end coverage of the wallet's navigable surface: every secondary-navigation action from the
/// home screen, plus the deep-link routing table that widgets, Control Center controls, and Siri
/// shortcuts all funnel through (`-deeplink <action>` exercises the same `apply(_:)` as those).
///
/// Honest scope: the NFC chip read (CoreNFC), the iProov liveness capture, and camera MRZ/QR scanning
/// are device-only — unavailable in the Simulator — so those flows are asserted up to the point their
/// entry screen appears, not through the OS hardware sheet.
final class WalletEndToEndUITests: XCTestCase {
    override func setUp() { continueAfterFailure = false }

    private func launch(
        autostart: String? = nil,
        deeplink: String? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> XCUIApplication {
        let app = XCUIApplication()
        if let autostart { app.launchArguments += ["-autostart", autostart] }
        if let deeplink { app.launchArguments += ["-deeplink", deeplink] }
        app.launch()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10), file: file, line: line)
        return app
    }

    private func exists(_ app: XCUIApplication, _ text: String, timeout: TimeInterval = 10) -> Bool {
        app.staticTexts[text].waitForExistence(timeout: timeout)
            || app.navigationBars[text].waitForExistence(timeout: 1)
    }

    // MARK: - Home + secondary navigation (tapping the real UI)

    func testHomePresentsAllSecondaryActions() {
        let app = launch(autostart: "home")
        XCTAssertTrue(app.staticTexts["Your documents"].waitForExistence(timeout: 10))
        for row in ["Add from passport", "Add web evidence", "Activity", "My Agents", "Settings"] {
            XCTAssertTrue(app.buttons[row].waitForExistence(timeout: 5), "missing home row: \(row)")
        }
    }

    func testAddFromPassportOpensReader() {
        let app = launch(autostart: "home")
        app.buttons["Add from passport"].tap()
        XCTAssertTrue(app.navigationBars["Add from passport"].waitForExistence(timeout: 10))
    }

    func testAddWebEvidenceOpensCaptureEntry() {
        let app = launch(autostart: "home")
        app.buttons["Add web evidence"].tap()
        XCTAssertTrue(app.navigationBars["Add web evidence"].waitForExistence(timeout: 10))
        XCTAssertTrue(exists(app, "TLSNotary web evidence"))
        XCTAssertTrue(app.buttons["Capture web evidence"].waitForExistence(timeout: 5))
    }

    func testManageAgentsOpens() {
        let app = launch(autostart: "home")
        app.buttons["My Agents"].tap()
        XCTAssertTrue(app.otherElements["agents.intro"].waitForExistence(timeout: 10)
            || app.staticTexts["agents.intro"].waitForExistence(timeout: 1))
    }

    // MARK: - Deep-link routing (same path as widgets / controls / Siri)

    func testDeepLinkScanOpensConnect() {
        let app = launch(deeplink: "scan")
        XCTAssertTrue(app.navigationBars["Scan a QR code"].waitForExistence(timeout: 10)
            || exists(app, "Add or use a document"))
    }

    func testDeepLinkPassportOpensReader() {
        let app = launch(deeplink: "passport")
        XCTAssertTrue(app.navigationBars["Add from passport"].waitForExistence(timeout: 10))
    }

    func testDeepLinkWebEvidenceOpensCapture() {
        let app = launch(deeplink: "web-evidence")
        XCTAssertTrue(app.navigationBars["Add web evidence"].waitForExistence(timeout: 10))
    }

    func testDeepLinkActivityOpensHistory() {
        let app = launch(deeplink: "activity")
        XCTAssertTrue(app.otherElements["activity.screen"].waitForExistence(timeout: 10)
            || app.navigationBars["Activity"].waitForExistence(timeout: 5))
    }

    func testDeepLinkCatalogueOpens() {
        let app = launch(deeplink: "catalogue")
        XCTAssertTrue(app.otherElements["catalogue.screen"].waitForExistence(timeout: 10)
            || app.navigationBars["Document catalogue"].waitForExistence(timeout: 5))
    }

    func testDeepLinkAgentsOpens() {
        let app = launch(deeplink: "agents")
        XCTAssertTrue(app.staticTexts["agents.intro"].waitForExistence(timeout: 10)
            || app.otherElements["agents.intro"].waitForExistence(timeout: 1))
    }

    func testDeepLinkSettingsOpens() {
        let app = launch(deeplink: "settings")
        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.buttons["settings.done"].waitForExistence(timeout: 5))
    }
}
