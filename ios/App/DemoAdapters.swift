import Foundation

/// Device signer for the simulator. Delegates to the Rust `DemoWallet`'s ephemeral P-256 key —
/// the stand-in for `SecureEnclaveSigner`, which needs real Secure Enclave hardware (absent on the
/// simulator). The signature validates against the device public key the core was given, so the
/// key binding / SCA dynamic linking the core performs is real.
final class DemoSigner: Signer {
    private let demo: DemoWallet
    init(demo: DemoWallet) { self.demo = demo }

    func sign(keyRef: String, payload: Data) throws -> Data {
        demo.signDevice(payload: payload)
    }
}

/// Supplies the RP certificate chain the core validates against its trusted list. The registration
/// DECISION is made in the Rust core — this only performs the "network" fetch (canned here).
final class DemoTrustResolver: TrustResolver {
    private let chain: [Data]
    private let uris: [String]
    init(certChain: [Data], redirectUris: [String]) {
        self.chain = certChain
        self.uris = redirectUris
    }

    func resolve(clientId: String) async -> (certChain: [Data], redirectUris: [String]) {
        (chain, uris)
    }
}

/// Stands in for the OpenID4VCI issuer's `/token` + `/credential` endpoints during a demo issuance.
/// A production shell POSTs these over TLS to a real issuer; here they return a fresh `c_nonce` and
/// the issuer-signed credential minted by the Rust `DemoWallet`. The core runs the full issuance
/// machine (trust gate, WUA key-attestation gate, device-signed proof) regardless — only the
/// transport is stubbed. `cNonce` must be unique per issuance (the core rejects a replayed one).
final class DemoIssuer: IssuerResponder {
    private let credentialCompact: Data
    private let cNonce: UInt64
    private let format: String

    init(credentialCompact: Data, cNonce: UInt64, format: String = "dc+sd-jwt") {
        self.credentialCompact = credentialCompact
        self.cNonce = cNonce
        self.format = format
    }

    func token() async -> (bound: Bool, cNonce: UInt64) { (true, cNonce) }

    func credential(proofJwt: Data) async -> (format: String, bytes: Data) {
        (format, credentialCompact)
    }
}
