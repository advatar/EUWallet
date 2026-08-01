import Foundation
import XCTest

private enum FrozenHybridVectorError: Error { case malformedHex }

private final class FrozenSignedHybridProviderTransport: ExperimentalPrivateProviderTransporting {
    func fetchHybridCredential(
        origin _: String,
        credentialConfigurationID: String
    ) async throws -> ExperimentalProviderCredentialResponse {
        ExperimentalProviderCredentialResponse(
            offeredKeyAgreementProfiles: ["euwallet-hybrid-pq-v1"],
            credentialConfigurationID: credentialConfigurationID,
            credentialFormat: "dev-hybrid-pq+cbor",
            wrapper: try loadHybridVector("hybrid-pq-v1-wrapper-envelope.hex"),
            publicKeyEnvelope: try loadHybridVector("hybrid-pq-v1-public-key-envelope.hex"),
            classicalKeyID: "shared-classical-kid-v1",
            postQuantumKeyID: "shared-pq-kid-v1",
            keyGeneration: 9,
            transactionID: Data("transaction-123".utf8),
            nonce: Data((0 ..< 32).map(UInt8.init)))
    }
}

final class HybridProviderIntegrationTests: XCTestCase {
    func testFrozenVCIssuerWrapperPassesRealRustVerificationAndStaysExperimental() async throws {
        let catalogue = ExperimentalCredentialCatalogue()
        let acquisition = ExperimentalHybridCredentialAcquisition(
            allowedOrigins: ["https://issuer.example"],
            transport: FrozenSignedHybridProviderTransport(),
            verifier: FfiExperimentalPqBackend(),
            catalogue: catalogue)

        let credential = try await acquisition.acquire(
            origin: "https://issuer.example",
            walletIdentity: Data("FNTotPeVek-MEChStrtHEZ9__f_R0R6CnaCg3QzzSQw".utf8),
            nowEpochSeconds: 1_700_000_100)

        XCTAssertEqual(
            credential.namespacedType,
            "urn:advatar:experimental:pq:vcissuer-hybrid-credential-v1")
        XCTAssertEqual(credential.keyGeneration, 9)
        XCTAssertEqual(credential.issuerOrigin, "https://issuer.example")
        XCTAssertEqual(catalogue.all(), [credential])
        XCTAssertFalse(credential.satisfiesProductionRequest("eu.europa.ec.eudi.pid.1"))
        XCTAssertFalse(credential.satisfiesProductionRequest("org.iso.18013.5.1.mDL"))
    }
}

private func loadHybridVector(_ name: String) throws -> Data {
    let repositoryRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let text = try String(
        contentsOf: repositoryRoot
            .appendingPathComponent("docs/test-vectors")
            .appendingPathComponent(name),
        encoding: .utf8)
    let hex = Array(text.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
    guard hex.count.isMultiple(of: 2) else { throw FrozenHybridVectorError.malformedHex }
    var bytes = Data(capacity: hex.count / 2)
    for offset in stride(from: 0, to: hex.count, by: 2) {
        guard let high = hexDigit(hex[offset]), let low = hexDigit(hex[offset + 1])
        else { throw FrozenHybridVectorError.malformedHex }
        bytes.append(high << 4 | low)
    }
    return bytes
}

private func hexDigit(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 48 ... 57: byte - 48
    case 65 ... 70: byte - 65 + 10
    case 97 ... 102: byte - 97 + 10
    default: nil
    }
}
