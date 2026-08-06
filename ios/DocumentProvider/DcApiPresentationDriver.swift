import Foundation

// WalletShell sources, the generated UniFFI bindings, and App/DemoAdapters.swift are compiled
// straight into this extension module (see ios/project.yml) — the same composition the host app
// uses — so no cross-module import is required.

#if canImport(wallet_coreFFI)

    /// Runs a Digital Credentials API (OpenID4VP-over-DC-API) mobile-document presentation end to
    /// end, inside the `IdentityDocumentServicesUI` provider extension, against the REAL Rust wallet
    /// core.
    ///
    /// This first release is **self-contained and demo-seeded**: it owns a single `DemoWallet` whose
    /// P-256 device key it also signs `DeviceAuthentication` with, so the PID mdoc it seeds (MSO
    /// `deviceKey` = that same key) and the DeviceAuth signature it returns are mutually consistent —
    /// a genuinely verifiable `DeviceResponse`, produced with no cross-process state and no shared
    /// keychain. That deliberately sidesteps the security-critical migration that would let the
    /// extension present the holder's *actual* credentials from the host app's durable store (a
    /// shared app-group container + `kSecAttrAccessGroup` on the Secure Enclave key); that migration
    /// is tracked separately because it must be validated with the device in the loop before it can
    /// touch the real device key.
    ///
    /// The wallet core still does all the real work: it parses the DC-API request, binds the
    /// `DeviceAuthentication` byte-for-byte to the `OpenID4VPDCAPIHandover` (Origin + nonce), enforces
    /// data minimisation (discloses only the requested elements), and assembles the `vp_token`.
    ///
    /// Threading: constructed and driven inside the `sendResponse` `@Sendable` closure, so it captures
    /// no non-Sendable state across a concurrency boundary. UniFFI objects carry their own Rust-side
    /// locking, so the off-main drive is safe.
    final class DcApiPresentationDriver {
        enum DriverError: Error, CustomStringConvertible {
            case seedFailed(String)
            case noConsentRender
            case noSignRequest
            case noResponse
            case coreDecode(String)

            var description: String {
                switch self {
                case .seedFailed(let why): return "Could not seed the demo PID mdoc: \(why)"
                case .noConsentRender: return "Core did not render a DC-API consent decision"
                case .noSignRequest: return "Core did not request a device signature"
                case .noResponse: return "Core did not emit a DC-API response"
                case .coreDecode(let why): return "Could not decode core output: \(why)"
                }
            }
        }

        private let demo: DemoWallet
        private let issuance: IssuanceScenario
        private let scenario: DemoScenario
        private let runtime: FfiWalletRuntime
        private var nonceCounter: UInt64 = 1
        private var seeded = false

        init() throws {
            let demo = DemoWallet()
            let issuance = demo.issuanceScenario()
            self.demo = demo
            self.issuance = issuance
            self.scenario = demo.scenario()
            self.runtime = try FfiWalletRuntime.ephemeralDemo(
                applicationIdentifier: "eu.advatar.wallet.demo.dc-api",
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

        private func nextNonce() -> UInt64 {
            nonceCounter += 1
            return nonceCounter
        }

        /// Seed the ARF-mandated PID mdoc (doctype `eu.europa.ec.eudi.pid.1`) into the demo engine by
        /// running the real OpenID4VCI issuance cascade — exactly the silent step the host app runs
        /// before the SD-JWT half. Idempotent. Drives the durable `lifecycle` (a mutating flow), so
        /// the holding is committed into the same engine the presentation then reads.
        func seedIfNeeded() async throws {
            guard !seeded else { return }
            let capture = ReviewCapture()
            let executor = EffectExecutor(
                lifecycle: runtime.lifecycle,
                signer: DemoSigner(demo: demo),
                http: StubHttpClient(),
                storage: InMemoryStorage(),
                trust: DemoTrustResolver(
                    certChain: scenario.rpCertChain,
                    redirectUris: scenario.registeredRedirectUris),
                issuer: DemoIssuer(
                    credentialCompact: Data(issuance.pidMdocCredential.utf8),
                    cNonce: nextNonce(),
                    format: "mso_mdoc"),
                render: { operationId, authorizationHash, _ in
                    capture.record(operationId: operationId, authorizationHash: authorizationHash)
                })
            let offer = Data(
                #"{"format":"mso_mdoc","grant":"pre-authorized","tx_code_required":false}"#.utf8)
            do {
                _ = try await executor.send(
                    eventJson: WalletEventJSON.credentialOfferReceived(
                        offer: offer,
                        issuerCertChain: issuance.issuerCertChain,
                        issuerId: issuance.issuerId))
                let (operationId, authorizationHash) = capture.value()
                guard let operationId, let authorizationHash else {
                    throw DriverError.seedFailed("issuer offer produced no reviewable decision")
                }
                _ = try await executor.send(
                    eventJson: WalletEventJSON.credentialOfferAccepted(
                        operationId: operationId,
                        authorizationHash: authorizationHash))
            } catch let error as DriverError {
                throw error
            } catch {
                throw DriverError.seedFailed(error.localizedDescription)
            }
            seeded = true
        }

        /// Drive the DC-API presentation and return the browser response bytes. For
        /// `response_mode=dc_api` the core emits the OpenID4VP `{"vp_token":{"<id>":["<b64url>"]}}`
        /// JSON object (UTF-8) — the payload the browser hands back to the verifier.
        ///
        /// The device-facing consent gesture already happened (the holder tapped **Share** in the
        /// system-hosted scene); the core's own `dcApiConsent` screen is consumed here to obtain the
        /// WYSIWYS `operationId` + `authorizationHash`, which the immediate `userConsented` echoes so
        /// the decision binds to exactly the request the core just parsed.
        func present(requestData: Data, origin: String) throws -> Data {
            // 1. Feed the OS-authenticated request → the core parses it, decides data minimisation,
            //    and renders the DC-API consent decision (carrying the WYSIWYS operationId + hash).
            let rendered = try effects(
                WalletEventJSON.dcApiRequestReceived(request: requestData, origin: origin))
            guard let (operationId, authorizationHash) = consentDecision(in: rendered) else {
                throw DriverError.noConsentRender
            }

            // 2. Consent → the core asks the device to sign the DeviceAuthentication.
            let afterConsent = try effects(
                WalletEventJSON.userConsented(
                    operationId: operationId, authorizationHash: Data(authorizationHash)))
            guard let (signOperationId, payload) = signRequest(in: afterConsent) else {
                throw DriverError.noSignRequest
            }

            // 3. The demo device key signs the exact bytes the core bound to the handover.
            let signature = demo.signDevice(payload: Data(payload))

            // 4. Signature accepted → the core assembles and emits the DC-API vp_token response.
            let afterSignature = try effects(
                WalletEventJSON.deviceSignatureProduced(
                    operationId: signOperationId, signature: signature))
            guard let response = dcApiResponse(in: afterSignature) else {
                throw DriverError.noResponse
            }
            return Data(response)
        }

        // MARK: - Effect decoding

        private func effects(_ eventJson: String) throws -> [WalletEffect] {
            let output = runtime.drivePresentationEvent(eventJson)
            do {
                return try WalletEffect.decodeCoreOutput(output)
            } catch {
                throw DriverError.coreDecode(error.localizedDescription)
            }
        }

        private func consentDecision(in effects: [WalletEffect]) -> (UInt64, [UInt8])? {
            for effect in effects {
                if case let .render(operationId?, authorizationHash?, screen) = effect,
                    case .dcApiConsent = screen
                {
                    return (operationId, authorizationHash)
                }
            }
            return nil
        }

        private func signRequest(in effects: [WalletEffect]) -> (UInt64, [UInt8])? {
            for effect in effects {
                if case let .sign(operationId, _, payload) = effect {
                    return (operationId, payload)
                }
            }
            return nil
        }

        private func dcApiResponse(in effects: [WalletEffect]) -> [UInt8]? {
            for effect in effects {
                if case let .emitDcApiResponse(response) = effect {
                    return response
                }
            }
            return nil
        }
    }

    /// Captures the `operationId` + `authorizationHash` the core stamps on a silent (non-reviewed)
    /// issuance render, so the seed cascade can echo them back on `credentialOfferAccepted`. Mirrors
    /// the host app's `IssuanceReviewCapture`; kept local so the extension has no App-only dependency.
    private final class ReviewCapture: @unchecked Sendable {
        private let lock = NSLock()
        private var operationId: UInt64?
        private var authorizationHash: Data?

        func record(operationId: UInt64?, authorizationHash: Data?) {
            lock.lock()
            defer { lock.unlock() }
            self.operationId = operationId
            self.authorizationHash = authorizationHash
        }

        func value() -> (UInt64?, Data?) {
            lock.lock()
            defer { lock.unlock() }
            return (operationId, authorizationHash)
        }
    }

#endif
