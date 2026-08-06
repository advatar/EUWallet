import XCTest

/// Proves the by-value credential-ingest path a cross-device PID capture uses: a single
/// `openid-credential-offer` carries BOTH ARF halves of the captured PID (SD-JWT + mso_mdoc), and
/// the wallet ingests each via `FfiWalletRuntime.ingestCredential` — the core AUTHENTICATES before
/// storing (SD-JWT against the issuer cert chain, mdoc against its embedded x5chain). Runs on the
/// simulator against the REAL Rust core. The OS deep-link/URL-scheme wiring is app glue tested
/// separately; this proves the storage boundary itself handles both formats from one offer.
final class Dc5CaptureIngestTests: XCTestCase {
    private func makeRuntime(_ issuance: IssuanceScenario) throws -> FfiWalletRuntime {
        try FfiWalletRuntime.ephemeralDemo(
            applicationIdentifier: "eu.advatar.wallet.demo.dc5",
            walletClientId: "wallet.example",
            deviceKeyReference: "device-key",
            environment: CoreDurableEnvironment(
                clockEpoch: issuance.epoch,
                signedTrustList: issuance.trustList,
                operatorPublicKey: issuance.operatorPublicKey,
                devicePublicKey: issuance.devicePublicKey,
                wuaJwt: issuance.wuaJwt,
                wuaProviderPublicKey: issuance.walletProviderPublicKey))
    }

    func testCaptureOfferIngestsBothFormats() throws {
        let demo = DemoWallet()
        let issuance = demo.issuanceScenario()
        let runtime = try makeRuntime(issuance)

        // The wallet holds nothing until the capture offer arrives.
        XCTAssertEqual(runtime.heldCredentialsJSON(), "[]")

        // SD-JWT half: authenticated against the issuer cert chain.
        let sdJwtError = runtime.ingestCredential(
            format: "dc+sd-jwt",
            credential: Data(issuance.pidCredentialCompact.utf8),
            issuerCertChain: issuance.issuerCertChain,
            issuerId: issuance.issuerId)
        XCTAssertEqual(sdJwtError, "", "SD-JWT PID must authenticate + store: \(sdJwtError)")

        // mdoc half: self-authenticates via its embedded x5chain, so the passed chain is empty.
        let mdocError = runtime.ingestCredential(
            format: "mso_mdoc",
            credential: Data(issuance.pidMdocCredential.utf8),
            issuerCertChain: [],
            issuerId: issuance.issuerId)
        XCTAssertEqual(mdocError, "", "PID mdoc must authenticate + store: \(mdocError)")

        // Both ARF formats of the captured PID are now held.
        let held = runtime.heldCredentialsJSON()
        XCTAssertTrue(held.contains("urn:eudi:pid:1"), "SD-JWT PID must be held: \(held)")
        XCTAssertTrue(held.contains("mso_mdoc"), "PID mdoc must be held: \(held)")
    }

    func testUnauthenticatedCredentialIsRejectedNotStored() throws {
        let demo = DemoWallet()
        let issuance = demo.issuanceScenario()
        let runtime = try makeRuntime(issuance)
        // A garbage SD-JWT with no valid issuer signature must be refused (not stored).
        let error = runtime.ingestCredential(
            format: "dc+sd-jwt",
            credential: Data("not.a.credential".utf8),
            issuerCertChain: issuance.issuerCertChain,
            issuerId: issuance.issuerId)
        XCTAssertNotEqual(error, "", "an unauthenticated credential must be rejected")
        XCTAssertEqual(runtime.heldCredentialsJSON(), "[]")
    }
}
