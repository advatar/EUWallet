import Foundation

/// Deterministic presentation-only wording. Protocol values remain untouched and continue to be
/// authorised by the Rust core; this layer only makes non-security metadata readable.
public enum ConsumerCopy {
    public static func claimName(_ raw: String) -> String {
        let retentionSuffix = " [retained]"
        let retained = raw.hasSuffix(retentionSuffix)
        let path = retained ? String(raw.dropLast(retentionSuffix.count)) : raw
        let key = path.split(separator: ".").last.map(String.init) ?? path
        let known = [
            "given_name": "Given name", "family_name": "Family name",
            "birth_date": "Date of birth", "birthdate": "Date of birth",
            "age_over_18": "Over 18", "portrait": "Portrait",
            "nationality": "Nationality", "document_number": "Document number",
            "driving_privileges": "Driving privileges", "expiry_date": "Expiry date"
        ]
        let label = known[key] ?? key.replacingOccurrences(of: "_", with: " ").capitalized
        return retained ? "\(label) (kept by requester)" : label
    }

    public static func activityName(_ raw: String) -> String {
        switch raw.lowercased() {
        case "presentation": return "Information shared"
        case "issuance": return "Document added"
        case "payment": return "Payment"
        case "qes": return "Document signed"
        default: return "Wallet activity"
        }
    }

    public static func outcomeName(_ raw: String) -> String {
        switch raw.lowercased() {
        case "success", "succeeded", "approved": return "Completed"
        case "declined": return "Not approved"
        case "failed", "error": return "Not completed"
        default: return "Completed"
        }
    }
}
