import CryptoKit
import Foundation

/// An ephemeral P-256 proof-of-possession key for one capture. The issued PID is bound to this key's
/// public JWK as `cnf`. This is a throwaway test wallet — the key lives only in memory for the run and
/// is never persisted; we only display the PID that comes back.
struct HolderKey {
    private let privateKey = P256.Signing.PrivateKey()

    /// RFC 7517 EC public JWK `{kty, crv, x, y}` with base64url (unpadded) coordinates — the exact
    /// shape VCIssuer's `POST /v1/pid-capture/session` expects as `holder_jwk`.
    var publicJwk: [String: String] {
        let raw = privateKey.publicKey.x963Representation // 0x04 ‖ X(32) ‖ Y(32)
        let x = raw.subdata(in: 1..<33)
        let y = raw.subdata(in: 33..<65)
        return ["kty": "EC", "crv": "P-256", "x": base64url(x), "y": base64url(y)]
    }

    private func base64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
