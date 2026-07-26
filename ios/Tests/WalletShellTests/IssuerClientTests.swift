import Foundation
import XCTest
@testable import WalletShell

private class IssuerTransportMock: IssuerRequesting, @unchecked Sendable {
    struct Request {
        let url: String
        let method: String
        let body: Data?
        let headers: [String: String]
    }

    private(set) var requests: [Request] = []
    var callbackState: String?

    func fetchCredentialOffer(uri: String) async throws -> HttpResponse {
        json([
            "credential_issuer": "https://issuer.example",
            "credential_configuration_ids": [LiveIssuerClient.tlsnotaryConfiguration],
            "grants": ["authorization_code": ["issuer_state": "issuer-state"]],
        ])
    }

    func fetchIssuerMetadata(issuer: String) async throws -> HttpResponse {
        json([
            "credential_issuer": issuer,
            "credential_endpoint": issuer + "/credential",
            "nonce_endpoint": issuer + "/nonce",
            "credential_configurations_supported": [
                LiveIssuerClient.tlsnotaryConfiguration: [
                    "format": "dc+sd-jwt",
                    "vct": LiveIssuerClient.tlsnotaryVct,
                    "scope": LiveIssuerClient.tlsnotaryConfiguration,
                    "credential_signing_certificate_endpoint": issuer
                        + "/credential-signing-certificates/"
                        + LiveIssuerClient.tlsnotaryConfiguration,
                ],
            ],
        ])
    }

    func issuerRequest(
        url: String, method: String, body: Data?, headers: [String: String],
        maximumResponseBytes: Int
    ) async throws -> HttpResponse {
        requests.append(Request(url: url, method: method, body: body, headers: headers))
        if url.contains("/credential-signing-certificates/") {
            return json([
                "credential_configuration_id": LiveIssuerClient.tlsnotaryConfiguration,
                "x5c": [Data([1, 2, 3]).base64EncodedString(),
                        Data([4, 5, 6]).base64EncodedString()],
                "development_only": true,
            ])
        }
        if url.hasSuffix("oauth-authorization-server") {
            return json([
                "issuer": "https://issuer.example",
                "authorization_endpoint": "https://issuer.example/authorize",
                "token_endpoint": "https://issuer.example/token",
                "pushed_authorization_request_endpoint": "https://issuer.example/par",
                "require_pushed_authorization_requests": true,
            ])
        }
        if url.hasSuffix("/par") {
            let fields = Self.formFields(body)
            callbackState = fields["state"]
            XCTAssertEqual(fields["code_challenge_method"], "S256")
            XCTAssertEqual(fields["issuer_state"], "issuer-state")
            return json(["request_uri": "urn:ietf:params:oauth:request_uri:one"])
        }
        if url.hasSuffix("/token") {
            XCTAssertNotNil(headers["DPoP"])
            XCTAssertEqual(Self.formFields(body)["code"], "authorization-code")
            return json(["access_token": "access-token", "token_type": "DPoP"])
        }
        if url.hasSuffix("/nonce") {
            return json(["c_nonce": "42"])
        }
        if url.hasSuffix("/credential") {
            XCTAssertEqual(headers["Authorization"], "DPoP access-token")
            XCTAssertNotNil(headers["DPoP"])
            let object = try JSONSerialization.jsonObject(with: body ?? Data()) as? [String: Any]
            let proofs = object?["proofs"] as? [String: Any]
            XCTAssertEqual(proofs?["jwt"] as? [String], ["holder.proof.jwt"])
            return json(["credentials": [["credential": "issuer.jwt~disclosure~"]]])
        }
        throw IssuerClientError.invalidConfiguration
    }

    private func json(_ object: [String: Any]) -> HttpResponse {
        HttpResponse(
            statusCode: 200,
            body: try! JSONSerialization.data(withJSONObject: object),
            contentType: "application/json")
    }

    private static func formFields(_ body: Data?) -> [String: String] {
        var components = URLComponents()
        components.percentEncodedQuery = String(data: body ?? Data(), encoding: .utf8)
        return Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).map {
            ($0.name, $0.value ?? "")
        })
    }
}

private final class IssuerAuthorizerMock: IssuerAuthorizationPresenting, @unchecked Sendable {
    let transport: IssuerTransportMock
    init(transport: IssuerTransportMock) { self.transport = transport }

    func authorize(url: URL, callbackScheme: String) async throws -> URL {
        XCTAssertEqual(callbackScheme, "euwallet")
        XCTAssertEqual(url.host, "issuer.example")
        guard let state = transport.callbackState else { throw IssuerClientError.invalidState }
        return URL(string: "euwallet://credential-callback?code=authorization-code&state=\(state)")!
    }
}

private final class IssuerSignerMock: Signer {
    private(set) var inputs: [Data] = []
    func sign(keyRef: String, payload: Data) throws -> Data {
        inputs.append(payload)
        return Data(repeating: 7, count: 64)
    }
}

final class IssuerClientTests: XCTestCase {
    func testTLSNotaryAuthorizationCodeFlowUsesPARPKCEDPoPNonceAndFinalProofArray() async throws {
        let transport = IssuerTransportMock()
        let signer = IssuerSignerMock()
        let client = try await LiveIssuerClient.discover(
            offerUri: "https://issuer.example/credential-offer/one",
            clientId: "wallet.example",
            redirectUri: "euwallet://credential-callback",
            keyReference: "device-key",
            publicKey: Data([4] + Array(repeating: 3, count: 64)),
            signer: signer,
            transport: transport,
            authorizer: IssuerAuthorizerMock(transport: transport))

        let pushed = try await client.pushAuthorizationRequest()
        XCTAssertEqual(client.context().signingLeaf, Data([1, 2, 3]))
        XCTAssertEqual(client.context().signingRoot, Data([4, 5, 6]))
        XCTAssertTrue(pushed)
        let code = try await client.authorize()
        XCTAssertEqual(code, Data("authorization-code".utf8))
        let token = try await client.token()
        XCTAssertTrue(token.bound)
        XCTAssertEqual(token.cNonce, 42)
        let credential = try await client.credential(proofJwt: Data("holder.proof.jwt".utf8))
        XCTAssertEqual(credential.format, "dc+sd-jwt")
        XCTAssertEqual(credential.bytes, Data("issuer.jwt~disclosure~".utf8))
        XCTAssertEqual(signer.inputs.count, 2)
        do {
            _ = try await client.credential(proofJwt: Data("holder.proof.jwt".utf8))
            XCTFail("a completed issuer session must not be replayed")
        } catch let error as IssuerClientError {
            XCTAssertEqual(error, .invalidState)
        }
    }

    func testDiscoveryRejectsAnIssuerEndpointOnAnotherOrigin() async throws {
        final class SubstitutionTransport: IssuerTransportMock, @unchecked Sendable {
            override func fetchIssuerMetadata(issuer: String) async throws -> HttpResponse {
                let response = try await super.fetchIssuerMetadata(issuer: issuer)
                var object = try JSONSerialization.jsonObject(with: response.body) as! [String: Any]
                object["credential_endpoint"] = "https://attacker.example/credential"
                return HttpResponse(
                    statusCode: 200,
                    body: try JSONSerialization.data(withJSONObject: object),
                    contentType: "application/json")
            }
        }
        let transport = SubstitutionTransport()
        do {
            _ = try await LiveIssuerClient.discover(
                offerUri: "https://issuer.example/credential-offer/one",
                clientId: "wallet.example", redirectUri: "euwallet://credential-callback",
                keyReference: "device-key", publicKey: Data([4] + Array(repeating: 3, count: 64)),
                signer: IssuerSignerMock(), transport: transport,
                authorizer: IssuerAuthorizerMock(transport: transport))
            XCTFail("endpoint substitution must fail")
        } catch let error as IssuerClientError {
            XCTAssertEqual(error, .invalidConfiguration)
        }
    }
}
