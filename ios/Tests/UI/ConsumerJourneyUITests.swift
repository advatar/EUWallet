import XCTest

final class ConsumerJourneyUITests: XCTestCase {
    private func launch(
        _ state: String,
        appearance: String? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["-autostart", state]
        if let appearance {
            app.launchArguments += ["-AppleInterfaceStyle", appearance]
        }
        app.launch()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10), file: file, line: line)
        return app
    }

    func testEmptyWalletHasOneClearAddAction() {
        let app = launch("home")

        XCTAssertTrue(app.staticTexts["Your documents"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Add your first document"].exists)
        XCTAssertEqual(app.buttons.matching(identifier: "home.add").count, 1)
        XCTAssertTrue(app.staticTexts["Activity"].exists)
        XCTAssertTrue(app.staticTexts["Settings"].exists)
    }

    func testSettingsUsesConsumerSectionsAndNavigationBarDismissal() {
        let app = launch("settings")

        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Privacy"].exists)
        XCTAssertTrue(app.staticTexts["You approve every request"].exists)
        XCTAssertTrue(app.staticTexts["Only share what is needed"].exists)
        XCTAssertTrue(app.staticTexts["On this iPhone"].exists)
        XCTAssertTrue(app.buttons["settings.done"].isHittable)
        XCTAssertFalse(app.buttons["Back"].exists)
        XCTAssertFalse(app.staticTexts["Protected on this device"].exists)
    }

    func testSettingsRemainsLegibleInDarkAppearance() {
        let app = launch("settings", appearance: "Dark")

        XCTAssertTrue(app.navigationBars["Settings"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Your phone confirms it is you"].exists)
        XCTAssertTrue(app.buttons["settings.done"].isHittable)
    }

    func testIssuanceOfferHasTrustedIssuerAndSafeActions() {
        let app = launch("add")

        XCTAssertTrue(
            app.staticTexts["Add your Digital identity document"].waitForExistence(timeout: 20))
        XCTAssertTrue(app.staticTexts["Verified issuer"].exists)
        XCTAssertTrue(app.buttons["issuance.add"].isHittable)
        XCTAssertTrue(app.buttons["issuance.cancel"].isHittable)
    }

    func testPaymentBindsAmountRecipientAndActions() {
        let app = launch("payment")

        XCTAssertTrue(app.staticTexts["Confirm payment"].waitForExistence(timeout: 20))
        XCTAssertEqual(app.staticTexts["payment.amount"].label, "12.99 EUR")
        XCTAssertTrue(app.staticTexts["Acme Store"].exists)
        XCTAssertTrue(app.buttons["payment.approve"].isHittable)
        XCTAssertTrue(app.buttons["payment.cancel"].isHittable)
    }

    func testConsentShowsSharingAndNotSharedInformationWithSafeActions() {
        let app = launch("consent")

        XCTAssertTrue(app.staticTexts["Sharing"].waitForExistence(timeout: 30))
        XCTAssertTrue(app.staticTexts["Not shared"].exists)
        XCTAssertTrue(app.buttons["consent.approve"].isHittable)
        XCTAssertTrue(app.buttons["consent.decline"].isHittable)
    }

    func testActivityUsesNativeTitleAndMaintenanceActions() {
        let app = launch("history")

        XCTAssertTrue(app.navigationBars["Activity"].waitForExistence(timeout: 20))
        XCTAssertTrue(app.buttons["Done"].isHittable)
        XCTAssertTrue(app.buttons["Save copy"].exists)
        XCTAssertTrue(app.buttons["Clear all"].exists)
    }

    func testCatalogueUsesHumanReadableDocumentInformation() {
        let app = launch("catalogue")

        XCTAssertTrue(app.navigationBars["Document catalogue"].waitForExistence(timeout: 20))
        XCTAssertTrue(app.staticTexts["Information this document may contain"].firstMatch.exists)
        XCTAssertFalse(app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS[c] %@", "dc+sd-jwt")).firstMatch.exists)
        XCTAssertTrue(app.buttons["Done"].isHittable)
    }
}
