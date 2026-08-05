import Foundation

/// One displayable claim from the issued PID.
struct PidClaim: Identifiable {
    let id = UUID()
    let key: String
    let value: String
}

/// Decode a PID for DISPLAY only — no signature verification, no persistence. This is a test wallet:
/// it shows the holder what the issuer minted, then forgets it.
enum PidDisplay {
    /// Extract the SD-JWT credential from an `openid-credential-offer://?credential_offer=<json>` deep
    /// link (VCIssuer carries the credential by value in `credentials[0].credential`).
    static func credential(fromOfferURL url: URL) -> String? {
        guard
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
            let offer = components.queryItems?.first(where: { $0.name == "credential_offer" })?.value,
            let data = offer.data(using: .utf8),
            let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let credentials = json["credentials"] as? [[String: Any]],
            let credential = credentials.first?["credential"] as? String
        else { return nil }
        return credential
    }

    /// Decode an SD-JWT VC (`<jwt>~<disclosure>~…~[<kb-jwt>]`) into displayable claims: the always-
    /// visible payload claims plus each selectively-disclosed `[salt, key, value]`.
    static func claims(fromSdJwt sdjwt: String) -> [PidClaim] {
        let parts = sdjwt.components(separatedBy: "~")
        var out: [PidClaim] = []

        // Issuer-signed JWT payload (first segment).
        if let jwt = parts.first {
            let segments = jwt.components(separatedBy: ".")
            if segments.count >= 2,
                let payload = decodeBase64url(segments[1]),
                let object = try? JSONSerialization.jsonObject(with: payload) as? [String: Any]
            {
                for key in ["vct", "iss", "given_name", "family_name", "birthdate", "nationality"] {
                    if let value = object[key], !(value is [String: Any]) {
                        out.append(PidClaim(key: key, value: "\(value)"))
                    }
                }
            }
        }

        // Disclosures: base64url([salt, key, value]). The optional trailing KB-JWT contains dots.
        for segment in parts.dropFirst() where !segment.isEmpty && !segment.contains(".") {
            if let data = decodeBase64url(segment),
                let array = try? JSONSerialization.jsonObject(with: data) as? [Any],
                array.count == 3, let key = array[1] as? String
            {
                out.append(PidClaim(key: key, value: "\(array[2])"))
            }
        }
        return out
    }

    private static func decodeBase64url(_ string: String) -> Data? {
        var s = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }
}
