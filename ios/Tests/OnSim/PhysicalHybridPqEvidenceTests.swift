import Foundation
import Security
import XCTest

#if canImport(UIKit)
    import UIKit
#endif

/// Evidence tests that execute only on a physical iPhone. Simulator and host suites skip these
/// rather than pretending software Keychain behavior proves Secure Enclave custody.
final class PhysicalHybridPqEvidenceTests: XCTestCase {
    private let wrappingKeyBytes = Data(repeating: 0x5a, count: 32)

    func testPhysicalPqBackendCorrectnessAndResourceMetrics() throws {
        #if targetEnvironment(simulator)
            throw XCTSkip("physical iPhone evidence only")
        #else
            let payload = Data("EUWALLET-PHYSICAL-PQ-EVIDENCE-V1".utf8)
            let material = try generateExperimentalPqWrappedKeyMaterial(
                wrappingKey: wrappingKeyBytes)
            XCTAssertEqual(material.nonce.count, 12)
            XCTAssertEqual(material.encryptedPrivateKey.count, 132)
            XCTAssertEqual(material.mlDsa65PublicKey.count, 1_952)
            XCTAssertEqual(material.mlKem768PublicKey.count, 1_184)
            XCTAssertEqual(
                try signExperimentalPqWrappedKeyMaterial(
                    wrappingKey: wrappingKeyBytes,
                    nonce: material.nonce,
                    encryptedPrivateKey: material.encryptedPrivateKey,
                    payload: payload
                ).count,
                3_309)

            measure(metrics: [XCTClockMetric(), XCTCPUMetric(), XCTMemoryMetric()]) {
                do {
                    let candidate = try generateExperimentalPqWrappedKeyMaterial(
                        wrappingKey: wrappingKeyBytes)
                    _ = try signExperimentalPqWrappedKeyMaterial(
                        wrappingKey: wrappingKeyBytes,
                        nonce: candidate.nonce,
                        encryptedPrivateKey: candidate.encryptedPrivateKey,
                        payload: payload)
                } catch {
                    XCTFail("physical hybrid-PQ operation failed: \(error)")
                }
            }
            attachDeviceRecord(caseName: "pq-backend-resource-metrics")
        #endif
    }

    func testPhysicalPqBackendBoundedConcurrency() throws {
        #if targetEnvironment(simulator)
            throw XCTSkip("physical iPhone evidence only")
        #else
            let lock = NSLock()
            var failures: [String] = []
            let started = ContinuousClock.now
            DispatchQueue.concurrentPerform(iterations: 4) { index in
                do {
                    let material = try generateExperimentalPqWrappedKeyMaterial(
                        wrappingKey: wrappingKeyBytes)
                    let signature = try signExperimentalPqWrappedKeyMaterial(
                        wrappingKey: wrappingKeyBytes,
                        nonce: material.nonce,
                        encryptedPrivateKey: material.encryptedPrivateKey,
                        payload: Data("concurrent-\(index)".utf8))
                    if signature.count != 3_309 {
                        lock.withLock { failures.append("signature-length-\(index)") }
                    }
                } catch {
                    lock.withLock { failures.append("operation-\(index):\(error)") }
                }
            }
            let elapsed = ContinuousClock.now - started
            XCTAssertTrue(failures.isEmpty, failures.joined(separator: ","))
            XCTAssertLessThan(elapsed, .milliseconds(100), "four concurrent operations exceeded budget")
            attachDeviceRecord(
                caseName: "pq-backend-concurrency",
                extra: ["operations": 4, "elapsed": "\(elapsed)"])
        #endif
    }

    @MainActor
    func testPhysicalPqSustainedConcurrencyBatteryAndThermalSnapshot() throws {
        #if targetEnvironment(simulator)
            throw XCTSkip("physical iPhone evidence only")
        #else
            UIDevice.current.isBatteryMonitoringEnabled = true
            defer { UIDevice.current.isBatteryMonitoringEnabled = false }
            let batteryBefore = UIDevice.current.batteryLevel
            let batteryStateBefore = UIDevice.current.batteryState.rawValue
            let thermalBefore = ProcessInfo.processInfo.thermalState.rawValue
            let deadline = ContinuousClock.now + .seconds(5)
            let lock = NSLock()
            var operations = 0
            var failures: [String] = []

            DispatchQueue.concurrentPerform(iterations: 4) { worker in
                while ContinuousClock.now < deadline {
                    do {
                        let material = try generateExperimentalPqWrappedKeyMaterial(
                            wrappingKey: wrappingKeyBytes)
                        let signature = try signExperimentalPqWrappedKeyMaterial(
                            wrappingKey: wrappingKeyBytes,
                            nonce: material.nonce,
                            encryptedPrivateKey: material.encryptedPrivateKey,
                            payload: Data("sustained-\(worker)".utf8))
                        guard signature.count == 3_309 else {
                            lock.withLock { failures.append("signature-length-\(worker)") }
                            break
                        }
                        lock.withLock { operations += 1 }
                    } catch {
                        lock.withLock { failures.append("operation-\(worker):\(error)") }
                        break
                    }
                }
            }

            let batteryAfter = UIDevice.current.batteryLevel
            let batteryStateAfter = UIDevice.current.batteryState.rawValue
            let thermalAfter = ProcessInfo.processInfo.thermalState.rawValue
            XCTAssertTrue(failures.isEmpty, failures.joined(separator: ","))
            XCTAssertGreaterThan(operations, 100, "sustained run did not exercise enough operations")
            XCTAssertNotEqual(
                ProcessInfo.processInfo.thermalState, .critical,
                "hybrid-PQ sustained concurrency reached critical thermal state")
            attachDeviceRecord(
                caseName: "pq-sustained-battery-thermal",
                extra: [
                    "durationSeconds": 5,
                    "workers": 4,
                    "operations": operations,
                    "batteryLevelBefore": batteryBefore,
                    "batteryLevelAfter": batteryAfter,
                    "batteryStateBefore": batteryStateBefore,
                    "batteryStateAfter": batteryStateAfter,
                    "thermalStateBefore": thermalBefore,
                    "thermalStateAfter": thermalAfter,
                ])
        #endif
    }

    func testPhysicalCustodyRotationRollbackAndCiphertextOnlyStorage() throws {
        #if targetEnvironment(simulator)
            throw XCTSkip("physical iPhone evidence only")
        #else
            let suffix = UUID().uuidString.lowercased()
            let logicalKeyID = "physical-pq-\(suffix)"
            let missingKeyID = "physical-pq-missing-\(suffix)"
            let serviceRoot = "eu.advatar.wallet.tests.experimental-pq.\(suffix)"
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("physical-pq-\(suffix)", isDirectory: true)
            defer {
                try? FileManager.default.removeItem(at: root)
                deleteKeychainService("\(serviceRoot).wrapping")
                deleteKeychainService("\(serviceRoot).generation")
                deleteSecureEnclaveKeys(logicalKeyIDs: [logicalKeyID, missingKeyID])
            }

            let wrappingKeys = AppleExperimentalPqWrappingKeyStore(
                service: "\(serviceRoot).wrapping")
            let records = try AppleExperimentalPqRecordStore(applicationSupportRoot: root)
            let anchors = AppleExperimentalPqGenerationAnchorStore(
                service: "\(serviceRoot).generation")
            let custody = ExperimentalHybridKeyCustody(
                signer: SecureEnclaveSigner(),
                backend: FfiExperimentalPqBackend(),
                wrappingKeys: wrappingKeys,
                records: records,
                anchors: anchors)

            let first = try custody.rotate(logicalKeyID: logicalKeyID, prompt: "Create test key")
            let firstRecord = try XCTUnwrap(records.load(logicalKeyID: logicalKeyID))
            let second = try custody.rotate(logicalKeyID: logicalKeyID, prompt: "Rotate test key")
            XCTAssertEqual(first.generation, 1)
            XCTAssertEqual(second.generation, 2)
            XCTAssertNotEqual(first.classicalKeyReference, second.classicalKeyReference)
            XCTAssertNotEqual(first.wrappedPqReference, second.wrappedPqReference)
            XCTAssertNotEqual(first.classicalPublicKeyHash, second.classicalPublicKeyHash)
            XCTAssertNotEqual(first.mlDsa65PublicKeyHash, second.mlDsa65PublicKeyHash)
            XCTAssertNotEqual(first.mlKem768PublicKeyHash, second.mlKem768PublicKeyHash)

            let custodyDirectory = root.appendingPathComponent(
                "ExperimentalPqCustody", isDirectory: true)
            let files = try FileManager.default.contentsOfDirectory(
                at: custodyDirectory,
                includingPropertiesForKeys: [.isExcludedFromBackupKey])
            XCTAssertEqual(files.count, 1)
            let raw = try Data(contentsOf: XCTUnwrap(files.first))
            XCTAssertNil(raw.range(of: Data("EUWALLET-PQ-SEEDS-V1".utf8)))
            XCTAssertTrue(
                try XCTUnwrap(files.first).resourceValues(forKeys: [.isExcludedFromBackupKey])
                    .isExcludedFromBackup == true)

            try records.commit(firstRecord)
            XCTAssertThrowsError(
                try custody.withUnlockedGeneration(
                    reference: second,
                    prompt: "Rollback must fail",
                    operation: { _, _ in XCTFail("rolled-back material was exposed") })
            ) { XCTAssertEqual($0 as? ExperimentalPqCustodyError, .rollbackDetected) }

            let missing = try custody.rotate(
                logicalKeyID: missingKeyID,
                prompt: "Create missing-key test")
            try wrappingKeys.delete(reference: missing.wrappedPqReference)
            XCTAssertThrowsError(
                try custody.withUnlockedGeneration(
                    reference: missing,
                    prompt: "Missing key must fail",
                    operation: { _, _ in XCTFail("missing key produced plaintext") })
            ) { XCTAssertEqual($0 as? ExperimentalPqCustodyError, .missingWrappingKey) }
            attachDeviceRecord(caseName: "custody-rotation-rollback-storage")
        #endif
    }

    /// Manual evidence gate. Set the environment variable to `approve` or `cancel`, then perform
    /// the matching biometric action on the connected iPhone. It is skipped in unattended CI.
    func testInteractivePhysicalBiometricGate() throws {
        #if targetEnvironment(simulator)
            throw XCTSkip("physical iPhone evidence only")
        #else
            guard let action = ProcessInfo.processInfo.environment["EUWALLET_PQ_BIOMETRIC_ACTION"],
                  action == "approve" || action == "cancel"
            else { throw XCTSkip("set EUWALLET_PQ_BIOMETRIC_ACTION=approve|cancel for manual evidence") }

            let suffix = UUID().uuidString.lowercased()
            let serviceRoot = "eu.advatar.wallet.tests.experimental-pq.interactive.\(suffix)"
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("physical-pq-interactive-\(suffix)", isDirectory: true)
            defer {
                try? FileManager.default.removeItem(at: root)
                deleteKeychainService("\(serviceRoot).wrapping")
                deleteKeychainService("\(serviceRoot).generation")
                deleteSecureEnclaveKeys(
                    logicalKeyIDs: ["physical-pq-interactive-\(suffix)"])
            }
            let custody = ExperimentalHybridKeyCustody(
                signer: SecureEnclaveSigner(),
                backend: FfiExperimentalPqBackend(),
                wrappingKeys: AppleExperimentalPqWrappingKeyStore(
                    service: "\(serviceRoot).wrapping"),
                records: try AppleExperimentalPqRecordStore(applicationSupportRoot: root),
                anchors: AppleExperimentalPqGenerationAnchorStore(
                    service: "\(serviceRoot).generation"))
            let reference = try custody.rotate(
                logicalKeyID: "physical-pq-interactive-\(suffix)",
                prompt: "Create interactive hybrid key")

            if action == "approve" {
                let signature = try custody.sign(
                    reference: reference,
                    payload: Data("interactive-physical-sign".utf8),
                    prompt: "Approve hybrid-PQ evidence test")
                XCTAssertEqual(signature.classicalSignature.count, 64)
                XCTAssertEqual(signature.postQuantumSignature.count, 3_309)
            } else {
                XCTAssertThrowsError(
                    try custody.sign(
                        reference: reference,
                        payload: Data("interactive-physical-cancel".utf8),
                        prompt: "Cancel hybrid-PQ evidence test")
                ) { error in
                    guard case .keychainFailure(let status) = error as? ExperimentalPqCustodyError
                    else { return XCTFail("unexpected cancellation error: \(error)") }
                    XCTAssertTrue(status == errSecUserCanceled || status == errSecAuthFailed)
                }
            }
            attachDeviceRecord(caseName: "biometric-\(action)")
        #endif
    }

    /// Manual evidence gate. Start while the device is unlocked, set the environment variable to
    /// `locked`, and lock the iPhone during the countdown. The protected wrapping key must remain
    /// unavailable and no signature may be returned.
    func testInteractivePhysicalLockedDeviceFailsClosed() throws {
        #if targetEnvironment(simulator)
            throw XCTSkip("physical iPhone evidence only")
        #else
            guard ProcessInfo.processInfo.environment["EUWALLET_PQ_DEVICE_STATE"] == "locked"
            else { throw XCTSkip("set EUWALLET_PQ_DEVICE_STATE=locked for manual evidence") }

            let suffix = UUID().uuidString.lowercased()
            let logicalKeyID = "physical-pq-locked-\(suffix)"
            let serviceRoot = "eu.advatar.wallet.tests.experimental-pq.locked.\(suffix)"
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("physical-pq-locked-\(suffix)", isDirectory: true)
            defer {
                try? FileManager.default.removeItem(at: root)
                deleteKeychainService("\(serviceRoot).wrapping")
                deleteKeychainService("\(serviceRoot).generation")
                deleteSecureEnclaveKeys(logicalKeyIDs: [logicalKeyID])
            }
            let custody = ExperimentalHybridKeyCustody(
                signer: SecureEnclaveSigner(),
                backend: FfiExperimentalPqBackend(),
                wrappingKeys: AppleExperimentalPqWrappingKeyStore(
                    service: "\(serviceRoot).wrapping"),
                records: try AppleExperimentalPqRecordStore(applicationSupportRoot: root),
                anchors: AppleExperimentalPqGenerationAnchorStore(
                    service: "\(serviceRoot).generation"))
            let reference = try custody.rotate(
                logicalKeyID: logicalKeyID,
                prompt: "Create locked-device evidence key")

            XCTContext.runActivity(named: "Lock the connected iPhone now; signing starts in 15 seconds") {
                _ in Thread.sleep(forTimeInterval: 15)
            }
            XCTAssertThrowsError(
                try custody.sign(
                    reference: reference,
                    payload: Data("locked-device-must-fail".utf8),
                    prompt: "Locked device must not unlock hybrid key")
            ) { error in
                guard case .keychainFailure(let status) = error as? ExperimentalPqCustodyError
                else { return XCTFail("unexpected locked-device error: \(error)") }
                XCTAssertTrue(
                    status == errSecInteractionNotAllowed || status == errSecAuthFailed
                        || status == errSecUserCanceled,
                    "unexpected locked-device Keychain status: \(status)")
            }
            attachDeviceRecord(caseName: "locked-device-fail-closed")
        #endif
    }

    private func attachDeviceRecord(caseName: String, extra: [String: Any] = [:]) {
        #if canImport(UIKit)
            var record: [String: Any] = [
                "case": caseName,
                "deviceName": UIDevice.current.name,
                "deviceModel": UIDevice.current.model,
                "systemName": UIDevice.current.systemName,
                "systemVersion": UIDevice.current.systemVersion,
                "timestamp": ISO8601DateFormatter().string(from: Date()),
            ]
            extra.forEach { record[$0] = $1 }
            let data = try! JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
            let attachment = XCTAttachment(data: data, uniformTypeIdentifier: "public.json")
            attachment.name = "hybrid-pq-physical-evidence-\(caseName).json"
            attachment.lifetime = .keepAlways
            add(attachment)
        #endif
    }

    private func deleteKeychainService(_ service: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: true,
        ] as CFDictionary)
    }

    private func deleteSecureEnclaveKeys(logicalKeyIDs: [String]) {
        for logicalKeyID in logicalKeyIDs {
            for generation in 1 ... 3 {
                SecItemDelete([
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: Data(
                        "\(logicalKeyID).hybrid.\(generation).p256".utf8),
                ] as CFDictionary)
            }
        }
    }
}
