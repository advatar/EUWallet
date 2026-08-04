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

    // Default service-nfc relay endpoint (editable + remembered once you change it).
    @AppStorage("nfc.serverURL") private var serverURL = "wss://nfc.dev-eu.iproov.id/channel"
    @State private var documentNumber = ""
    @State private var dateOfBirth = ""
    @State private var dateOfExpiry = ""
    @State private var scannedMrz: String?
    @State private var showScanner = false
    @State private var reading = false
    @State private var errorMessage: String?
    @State private var result: PassportReadResult?

    private var manualComplete: Bool {
        !documentNumber.isEmpty && dateOfBirth.count == 6 && dateOfExpiry.count == 6
    }

    private var canRead: Bool {
        !reading && serverURL.hasPrefix("ws") && (scannedMrz != nil || manualComplete)
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
                    Button {
                        showScanner = true
                    } label: {
                        Label(
                            scannedMrz == nil ? "Scan MRZ with camera" : "Re-scan MRZ",
                            systemImage: "camera.viewfinder")
                    }
                    if scannedMrz != nil {
                        HStack {
                            Label("MRZ scanned", systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                            Spacer()
                            Button("Clear") { scannedMrz = nil }.font(.footnote)
                        }
                    } else {
                        TextField("Document number", text: $documentNumber)
                            .textInputAutocapitalization(.characters)
                            .autocorrectionDisabled()
                        TextField("Date of birth — YYMMDD", text: $dateOfBirth)
                            .keyboardType(.numberPad)
                        TextField("Date of expiry — YYMMDD", text: $dateOfExpiry)
                            .keyboardType(.numberPad)
                    }
                } header: {
                    Text("From the passport's data page")
                } footer: {
                    Text(
                        scannedMrz == nil
                            ? "Scan the two machine-readable lines at the bottom of the data page, or type the fields."
                            : "Using the scanned MRZ. Tap Clear to type the fields instead.")
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
            .sheet(isPresented: $showScanner) {
                NavigationStack {
                    MRZScannerView { mrz in
                        scannedMrz = mrz
                        showScanner = false
                    }
                    .ignoresSafeArea()
                    .overlay(alignment: .bottom) {
                        Text("Point at the machine-readable zone (the <<< lines)")
                            .font(.footnote).padding(8)
                            .background(.ultraThinMaterial, in: Capsule())
                            .padding(.bottom, 24)
                    }
                    .navigationTitle("Scan MRZ")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") { showScanner = false }
                        }
                    }
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
            let input: PassportMrzInput
            if let scannedMrz {
                input = .raw(scannedMrz)
            } else {
                input = .fields(
                    number: documentNumber.trimmingCharacters(in: .whitespaces),
                    dateOfBirth: dateOfBirth,
                    dateOfExpiry: dateOfExpiry)
            }
            let read = try await reader.read(serverURL: serverURL, mrz: input)
            result = read
            onComplete(read)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
