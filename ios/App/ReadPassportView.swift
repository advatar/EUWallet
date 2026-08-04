import SwiftUI
import UIKit

/// "Add from passport (NFC)": reads an eMRTD chip over NFC (via the ChipmunkNFC relay to a
/// `service-nfc` backend) and hands the result back to the wallet. The device is a relay, so it
/// needs the server URL (wss://host/channel) — enter it once; it is remembered.
///
/// The MRZ fields (document number + dates) come from the printed data page and derive the BAC/PACE
/// key the chip requires. Camera OCR of the MRZ and the iProov liveness step are the next layer;
/// this screen is the on-device NFC read + result.
struct ReadPassportView: View {
    @Environment(\.dismiss) private var dismiss
    let reader: PassportReading
    let onComplete: (PassportReadResult) -> Void

    @AppStorage("nfc.serverURL") private var serverURL = ""
    @State private var documentNumber = ""
    @State private var dateOfBirth = ""
    @State private var dateOfExpiry = ""
    @State private var reading = false
    @State private var errorMessage: String?
    @State private var result: PassportReadResult?

    private var canRead: Bool {
        !reading
            && serverURL.hasPrefix("ws")
            && !documentNumber.isEmpty
            && dateOfBirth.count == 6
            && dateOfExpiry.count == 6
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("wss://your-host/channel", text: $serverURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                } header: {
                    Text("NFC reader server")
                } footer: {
                    Text("The reader relays to your service-nfc backend, which runs the chip protocol.")
                }

                Section {
                    TextField("Document number", text: $documentNumber)
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                    TextField("Date of birth — YYMMDD", text: $dateOfBirth)
                        .keyboardType(.numberPad)
                    TextField("Date of expiry — YYMMDD", text: $dateOfExpiry)
                        .keyboardType(.numberPad)
                } header: {
                    Text("From the passport's data page")
                } footer: {
                    Text("These derive the key the chip requires (BAC/PACE). Camera scanning of the MRZ is coming next.")
                }

                if let errorMessage {
                    Section {
                        Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }

                if let result {
                    Section("Read from the chip") {
                        if let portrait = result.portrait, let image = UIImage(data: portrait) {
                            HStack {
                                Spacer()
                                Image(uiImage: image)
                                    .resizable().scaledToFit().frame(height: 140)
                                    .clipShape(RoundedRectangle(cornerRadius: 8))
                                Spacer()
                            }
                        }
                        LabeledContent("Name", value: result.holderName.isEmpty ? "—" : result.holderName)
                        LabeledContent("Document", value: result.documentNumber)
                        LabeledContent("Nationality", value: result.nationality.isEmpty ? "—" : result.nationality)
                        LabeledContent("Date of birth", value: result.dateOfBirth)
                        LabeledContent("Expires", value: result.dateOfExpiry)
                    }
                }

                Section {
                    Button(action: { Task { await performRead() } }) {
                        HStack {
                            if reading { ProgressView().padding(.trailing, 4) }
                            Text(reading ? "Hold passport to your iPhone…" : "Read passport (NFC)")
                                .fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .disabled(!canRead)
                }
            }
            .navigationTitle("Add from passport")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func performRead() async {
        errorMessage = nil
        result = nil
        reading = true
        defer { reading = false }
        do {
            let read = try await reader.read(
                serverURL: serverURL,
                passportNumber: documentNumber.trimmingCharacters(in: .whitespaces),
                dateOfBirth: dateOfBirth,
                dateOfExpiry: dateOfExpiry)
            result = read
            onComplete(read)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
