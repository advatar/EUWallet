import SwiftUI

/// One selectable field discovered in a JSON/API response, identified by its RFC 6901 JSON Pointer
/// (e.g. `/account`, `/user/name`, `/items/0/id`) with a short preview of its value.
struct DisclosureField: Identifiable, Hashable {
    var id: String { pointer }
    let pointer: String
    let preview: String
}

/// Flattens a JSON response into the leaf fields a holder can choose to disclose. Only makes sense
/// for structured (JSON/API) responses — each leaf maps to a contiguous span the TLSNotary prover can
/// reveal while redacting the rest.
enum JSONDisclosure {
    /// Cap on discovered fields so a pathological response can't produce an unusable list.
    private static let maxFields = 200

    /// Parse `data` as JSON and return its leaf fields as JSON Pointers. Returns `nil` when the body
    /// is not a JSON object/array (field-level selection only applies to structured responses).
    static func fields(from data: Data) -> [DisclosureField]? {
        guard let root = try? JSONSerialization.jsonObject(
            with: data, options: [.fragmentsAllowed]),
            root is [String: Any] || root is [Any]
        else { return nil }
        var out: [DisclosureField] = []
        flatten(root, pointer: "", into: &out)
        return out
    }

    private static func flatten(_ value: Any, pointer: String, into out: inout [DisclosureField]) {
        guard out.count < maxFields else { return }
        switch value {
        case let object as [String: Any]:
            for key in object.keys.sorted() {
                flatten(object[key] as Any, pointer: pointer + "/" + escape(key), into: &out)
            }
        case let array as [Any]:
            for (index, element) in array.enumerated() {
                flatten(element, pointer: pointer + "/" + String(index), into: &out)
            }
        default:
            // A leaf (string/number/bool/null). An empty pointer means the whole body was a scalar.
            let leafPointer = pointer.isEmpty ? "/" : pointer
            out.append(DisclosureField(pointer: leafPointer, preview: previewText(value)))
        }
    }

    /// RFC 6901 token escaping: `~` → `~0`, `/` → `~1`.
    private static func escape(_ token: String) -> String {
        token.replacingOccurrences(of: "~", with: "~0")
            .replacingOccurrences(of: "/", with: "~1")
    }

    private static func previewText(_ value: Any) -> String {
        let raw: String
        switch value {
        case is NSNull: raw = "null"
        case let string as String: raw = string
        case let number as NSNumber: raw = number.stringValue
        default: raw = String(describing: value)
        }
        return raw.count > 48 ? String(raw.prefix(48)) + "…" : raw
    }
}

/// A sheet letting the holder choose which fields of a JSON response go into the evidence proof.
///
/// HONEST SCOPE: this is the selection/consent surface. The chosen JSON Pointers are recorded in the
/// evidence credential's `credentialSubject.disclosedFields` and are the exact input the prover core
/// will use to reveal only those transcript ranges (and redact the rest). Until that core redaction
/// lands, unselected fields are simply not listed as disclosed — they are not yet cryptographically
/// stripped from the underlying attestation.
struct DisclosureFieldPicker: View {
    let fields: [DisclosureField]
    @Binding var selected: Set<String>
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(fields) { field in
                        Button {
                            toggle(field.pointer)
                        } label: {
                            HStack(spacing: 12) {
                                Image(systemName: selected.contains(field.pointer)
                                    ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(selected.contains(field.pointer)
                                        ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(field.pointer).font(.subheadline.monospaced())
                                    Text(field.preview).font(.caption).foregroundStyle(.secondary)
                                        .lineLimit(1)
                                }
                            }
                        }
                        .buttonStyle(.plain)
                    }
                } header: {
                    Text("\(selected.count) of \(fields.count) fields disclosed")
                } footer: {
                    Text("Only the selected fields are recorded as disclosed in the proof. Deselect a field to keep it private.")
                }
            }
            .navigationTitle("Fields to disclose")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(selected.count == fields.count ? "None" : "All") {
                        selected = selected.count == fields.count
                            ? [] : Set(fields.map(\.pointer))
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private func toggle(_ pointer: String) {
        if selected.contains(pointer) { selected.remove(pointer) } else { selected.insert(pointer) }
    }
}
