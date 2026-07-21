import CryptoKit
import Darwin
import Foundation
import Security
import XCTest

@testable import WalletShell

final class DurableStateStoreTests: XCTestCase {
    func testEmptyFirstRunDoesNotCreateKeyAnchorOrSlots() throws {
        let harness = try Harness()

        XCTAssertEqual(try harness.store.load(context: harness.context), .empty)
        XCTAssertNil(harness.metadata.key)
        XCTAssertNil(harness.metadata.anchor)
        XCTAssertFalse(try harness.fileSystem.hasAnySlot())
    }

    func testCommitLoadAndSlotRotationUseExactGenerations() throws {
        let harness = try Harness()
        let first = Data("first canonical checkpoint".utf8)
        let second = Data("second canonical checkpoint".utf8)

        XCTAssertEqual(
            try harness.store.commit(
                expectedGeneration: 0,
                nextGeneration: 1,
                plaintext: first,
                context: harness.context),
            DurableStateRecord(generation: 1, plaintext: first))
        XCTAssertEqual(
            try harness.store.load(context: harness.context),
            .record(DurableStateRecord(generation: 1, plaintext: first)))
        XCTAssertTrue(FileManager.default.fileExists(atPath: harness.fileSystem.slotURL(.a).path))

        try harness.store.commit(
            expectedGeneration: 1,
            nextGeneration: 2,
            plaintext: second,
            context: harness.context)
        XCTAssertEqual(
            try harness.store.load(context: harness.context),
            .record(DurableStateRecord(generation: 2, plaintext: second)))
        XCTAssertTrue(FileManager.default.fileExists(atPath: harness.fileSystem.slotURL(.b).path))
        XCTAssertEqual(harness.metadata.createKeyCalls, 1)
        XCTAssertEqual(harness.metadata.createAnchorCalls, 1)
        XCTAssertEqual(harness.metadata.replaceAnchorCalls, 2)
    }

    func testCasMismatchAndNonSequentialGenerationFailBeforeMutation() throws {
        let harness = try Harness()
        try harness.commit(generation: 1, value: "one")
        let anchor = harness.metadata.anchor

        XCTAssertThrowsError(
            try harness.store.commit(
                expectedGeneration: 0,
                nextGeneration: 1,
                plaintext: Data("stale".utf8),
                context: harness.context)
        ) { error in
            XCTAssertEqual(
                error as? DurableStateStoreError,
                .generationConflict(expected: 0, actual: 1))
        }
        XCTAssertThrowsError(
            try harness.store.commit(
                expectedGeneration: 1,
                nextGeneration: 3,
                plaintext: Data("skip".utf8),
                context: harness.context)
        ) { error in
            XCTAssertEqual(
                error as? DurableStateStoreError,
                .invalidGenerationTransition(expected: 1, next: 3))
        }
        XCTAssertEqual(harness.metadata.anchor, anchor)
        XCTAssertEqual(
            try harness.store.load(context: harness.context),
            .record(DurableStateRecord(generation: 1, plaintext: Data("one".utf8))))
    }

    func testContextApplicationAndSchemaMismatchesFailClosed() throws {
        let harness = try Harness()
        try harness.commit(generation: 1, value: "bound")

        let wrongContext = try DurableStateContext(binding: Data("another-device-key".utf8))
        XCTAssertThrowsError(try harness.store.load(context: wrongContext)) { error in
            XCTAssertEqual(error as? DurableStateStoreError, .contextMismatch)
        }

        let wrongApplicationStore = try AppleDurableStateStore(
            applicationIdentifier: "de.example.other-wallet",
            metadata: harness.metadata,
            fileSystem: harness.fileSystem)
        XCTAssertThrowsError(try wrongApplicationStore.load(context: harness.context)) { error in
            XCTAssertEqual(error as? DurableStateStoreError, .applicationIdentityMismatch)
        }

        var anchor = try XCTUnwrap(harness.metadata.anchor)
        setUInt32(0, in: &anchor, at: AnchorOffset.schema)
        harness.metadata.anchor = anchor
        XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
            XCTAssertEqual(
                error as? DurableStateStoreError,
                .schemaMismatch(expected: 1, actual: 0))
        }
    }

    func testAeadAuthenticatesApplicationAndCallerBindingsBehindTheAnchor() throws {
        do {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "app-bound")
            let otherApplication = "de.example.other-wallet"
            var anchor = try XCTUnwrap(harness.metadata.anchor)
            anchor.replaceSubrange(
                AnchorOffset.applicationDigest..<(AnchorOffset.applicationDigest + 32),
                with: Data(SHA256.hash(data: Data(otherApplication.utf8))))
            harness.metadata.anchor = anchor
            let otherStore = try AppleDurableStateStore(
                applicationIdentifier: otherApplication,
                metadata: harness.metadata,
                fileSystem: harness.fileSystem)

            XCTAssertThrowsError(try otherStore.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .authenticationFailed)
            }
        }

        do {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "context-bound")
            let otherContext = try DurableStateContext(binding: Data("other-context".utf8))
            var anchor = try XCTUnwrap(harness.metadata.anchor)
            anchor.replaceSubrange(
                AnchorOffset.contextDigest..<(AnchorOffset.contextDigest + 32),
                with: Data(SHA256.hash(data: otherContext.binding)))
            harness.metadata.anchor = anchor

            XCTAssertThrowsError(try harness.store.load(context: otherContext)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .authenticationFailed)
            }
        }
    }

    func testFutureVersionsAndInvalidPublicContextsAreRejected() throws {
        XCTAssertThrowsError(try DurableStateContext(schemaVersion: 2, binding: Data([1]))) {
            error in
            XCTAssertEqual(error as? DurableStateStoreError, .unsupportedSchemaVersion(2))
        }
        XCTAssertThrowsError(try DurableStateContext(binding: Data())) { error in
            XCTAssertEqual(error as? DurableStateStoreError, .invalidContextLength(0))
        }
        XCTAssertThrowsError(
            try DurableStateContext(
                binding: Data(repeating: 1, count: DurableStateContext.maximumBindingBytes + 1))
        ) { error in
            XCTAssertEqual(
                error as? DurableStateStoreError,
                .invalidContextLength(DurableStateContext.maximumBindingBytes + 1))
        }

        do {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "anchor-version")
            var anchor = try XCTUnwrap(harness.metadata.anchor)
            setUInt16(2, in: &anchor, at: AnchorOffset.formatVersion)
            harness.metadata.anchor = anchor
            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .unsupportedAnchorVersion(2))
            }
        }

        do {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "envelope-version")
            try harness.mutateAnchoredEnvelope(updateDigest: true) { envelope in
                setUInt16(2, in: &envelope, at: EnvelopeOffset.formatVersion)
            }
            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .unsupportedEnvelopeVersion(2))
            }
        }

        do {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "future-schema")
            try harness.mutateAnchoredEnvelope(updateDigest: true) { envelope in
                setUInt32(2, in: &envelope, at: EnvelopeOffset.schema)
            }
            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .unsupportedSchemaVersion(2))
            }
        }
    }

    func testHeaderNonceCiphertextAndTagTamperingAreRejected() throws {
        try assertEnvelopeMutationRejected(
            expected: .corruptEnvelope,
            mutation: { $0[0] ^= 0x01 })
        try assertEnvelopeMutationRejected(
            expected: .authenticationFailed,
            mutation: { $0[EnvelopeOffset.nonce] ^= 0x01 })
        try assertEnvelopeMutationRejected(
            expected: .authenticationFailed,
            mutation: { $0[EnvelopeOffset.ciphertext] ^= 0x01 })
        try assertEnvelopeMutationRejected(
            expected: .authenticationFailed,
            mutation: { $0[$0.count - 1] ^= 0x01 })
    }

    func testStrictEnvelopeRejectsTruncationTrailingBytesLengthsAndOversize() throws {
        XCTAssertEqual(AppleDurableStateStore.maximumEnvelopeBytes, 32 * 1024 * 1024)
        XCTAssertLessThan(
            AppleDurableStateStore.maximumPlaintextBytes,
            AppleDurableStateStore.maximumEnvelopeBytes)
        try assertEnvelopeMutationRejected(
            expected: .corruptEnvelope,
            mutation: { $0.removeLast() })
        try assertEnvelopeMutationRejected(
            expected: .corruptEnvelope,
            mutation: { $0.append(0) })
        try assertEnvelopeMutationRejected(
            expected: .corruptEnvelope,
            mutation: { $0[EnvelopeOffset.nonceLength] = 13 })
        try assertEnvelopeMutationRejected(
            expected: .envelopeTooLarge(
                actual: Int(UInt32.max), maximum: AppleDurableStateStore.maximumPlaintextBytes),
            mutation: { setUInt32(UInt32.max, in: &$0, at: EnvelopeOffset.ciphertextLength) })

        let harness = try Harness()
        try harness.commit(generation: 1, value: "bounded")
        let oversized = Data(
            repeating: 0,
            count: AppleDurableStateStore.maximumEnvelopeBytes + 1)
        try harness.replaceAnchoredEnvelope(oversized, updateDigest: true)
        XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
            XCTAssertEqual(
                error as? DurableStateStoreError,
                .envelopeTooLarge(
                    actual: AppleDurableStateStore.maximumEnvelopeBytes + 1,
                    maximum: AppleDurableStateStore.maximumEnvelopeBytes))
        }

        XCTAssertThrowsError(
            try harness.store.commit(
                expectedGeneration: 1,
                nextGeneration: 2,
                plaintext: Data(
                    repeating: 0,
                    count: AppleDurableStateStore.maximumPlaintextBytes + 1),
                context: harness.context)
        ) { error in
            XCTAssertEqual(
                error as? DurableStateStoreError,
                .plaintextTooLarge(
                    actual: AppleDurableStateStore.maximumPlaintextBytes + 1,
                    maximum: AppleDurableStateStore.maximumPlaintextBytes))
        }
    }

    func testWrongKeyAndMissingKeyWithStateNeverRegenerate() throws {
        do {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "encrypted")
            harness.metadata.key = Data(repeating: 0x99, count: 32)
            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .authenticationFailed)
            }
        }

        do {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "state")
            harness.metadata.key = nil
            let createCalls = harness.metadata.createKeyCalls
            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .missingInstallationKey)
            }
            XCTAssertThrowsError(
                try harness.store.commit(
                    expectedGeneration: 1,
                    nextGeneration: 2,
                    plaintext: Data("must-not-regenerate".utf8),
                    context: harness.context)
            ) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .missingInstallationKey)
            }
            XCTAssertEqual(harness.metadata.createKeyCalls, createCalls)
        }
    }

    func testMissingCorruptAndStaleAnchorsFailClosed() throws {
        do {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "state")
            harness.metadata.anchor = nil
            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .missingAnchor)
            }
        }

        do {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "state")
            harness.metadata.anchor = Data([0x00])
            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .corruptAnchor)
            }
        }

        do {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "one")
            let generationOneAnchor = try XCTUnwrap(harness.metadata.anchor)
            try harness.commit(generation: 2, value: "two")
            try harness.commit(generation: 3, value: "three")
            // Slot A now holds generation 3. Restoring only its old generation-1 anchor is detected.
            harness.metadata.anchor = generationOneAnchor
            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .anchorDigestMismatch)
            }
        }
    }

    func testWrongSlotGenerationAndDigestAreRejected() throws {
        try assertEnvelopeMutationRejected(
            expected: .slotMismatch(expected: .a, actual: .b),
            mutation: { $0[EnvelopeOffset.slot] = DurableStateSlot.b.rawValue })

        try assertEnvelopeMutationRejected(
            expected: .generationMismatch(expected: 1, actual: 2),
            mutation: { setUInt64(2, in: &$0, at: EnvelopeOffset.generation) })

        let harness = try Harness()
        try harness.commit(generation: 1, value: "digest")
        try harness.mutateAnchoredEnvelope(updateDigest: false) { $0[0] ^= 1 }
        XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
            XCTAssertEqual(error as? DurableStateStoreError, .anchorDigestMismatch)
        }
    }

    func testCorruptAnchoredSlotNeverFallsBackToOlderValidSlot() throws {
        let harness = try Harness()
        try harness.commit(generation: 1, value: "old-valid")
        try harness.commit(generation: 2, value: "new-anchored")
        try harness.mutateAnchoredEnvelope(updateDigest: false) { $0[$0.count - 1] ^= 1 }

        XCTAssertTrue(FileManager.default.fileExists(atPath: harness.fileSystem.slotURL(.a).path))
        XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
            XCTAssertEqual(error as? DurableStateStoreError, .anchorDigestMismatch)
        }
    }

    func testMissingAnchoredSlotAndInvalidGenesisAnchorAreRejected() throws {
        do {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "state")
            try FileManager.default.removeItem(at: harness.fileSystem.slotURL(.a))
            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .missingAnchoredSlot(.a))
            }
        }

        do {
            let harness = try Harness(faultPoint: .afterGenesisAnchor)
            XCTAssertThrowsError(try harness.commit(generation: 1, value: "state")) { error in
                XCTAssertEqual(
                    error as? DurableStateStoreError,
                    .interruptedWrite(.afterGenesisAnchor))
            }
            var anchor = try XCTUnwrap(harness.metadata.anchor)
            anchor[AnchorOffset.envelopeDigest] = 1
            harness.metadata.anchor = anchor
            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .invalidGenesisAnchor)
            }
        }
    }

    func testEverySteadyStateFaultKeepsOldAnchorOrMakesNewAnchorReadable() throws {
        let oldStatePoints: [DurableStateFaultPoint] = [
            .beforeTemporaryCreate,
            .afterTemporaryCreate,
            .afterTemporaryWrite,
            .afterTemporarySync,
            .afterRename,
            .afterDirectorySync,
            .beforeAnchorUpdate,
        ]
        for point in oldStatePoints {
            let harness = try Harness()
            try harness.commit(generation: 1, value: "old")
            harness.faultInjector.arm(point)
            XCTAssertThrowsError(try harness.commit(generation: 2, value: "new")) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .interruptedWrite(point))
            }
            XCTAssertEqual(
                try harness.store.load(context: harness.context),
                .record(DurableStateRecord(generation: 1, plaintext: Data("old".utf8))),
                "fault at \(point) must retain the old anchored state")
        }

        let harness = try Harness()
        try harness.commit(generation: 1, value: "old")
        harness.faultInjector.arm(.afterAnchorUpdate)
        XCTAssertThrowsError(try harness.commit(generation: 2, value: "new")) { error in
            XCTAssertEqual(error as? DurableStateStoreError, .interruptedWrite(.afterAnchorUpdate))
        }
        XCTAssertEqual(
            try harness.store.load(context: harness.context),
            .record(DurableStateRecord(generation: 2, plaintext: Data("new".utf8))))
    }

    func testFailedAnchorUpdateLeavesNewSlotUnanchoredAndOldStateReadable() throws {
        let harness = try Harness()
        try harness.commit(generation: 1, value: "old")
        harness.metadata.failNextReplace = true

        XCTAssertThrowsError(try harness.commit(generation: 2, value: "new")) { error in
            XCTAssertEqual(
                error as? DurableStateStoreError,
                .secureMetadataFailure(operation: "test anchor update", status: -1))
        }
        XCTAssertEqual(
            try harness.store.load(context: harness.context),
            .record(DurableStateRecord(generation: 1, plaintext: Data("old".utf8))))
    }

    func testEveryFirstCommitFaultHasOnlyEmptyOrNewAnchoredStateAndCanRetry() throws {
        let emptyPoints: [DurableStateFaultPoint] = [
            .afterKeyCreation,
            .beforeGenesisAnchor,
            .afterGenesisAnchor,
            .beforeTemporaryCreate,
            .afterTemporaryCreate,
            .afterTemporaryWrite,
            .afterTemporarySync,
            .afterRename,
            .afterDirectorySync,
            .beforeAnchorUpdate,
        ]
        for point in emptyPoints {
            let harness = try Harness(faultPoint: point)
            XCTAssertThrowsError(try harness.commit(generation: 1, value: "new")) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .interruptedWrite(point))
            }
            XCTAssertEqual(
                try harness.store.load(context: harness.context),
                .empty,
                "fault at \(point) must not expose unanchored generation 1")
            XCTAssertEqual(harness.metadata.createKeyCalls, 1)
            try harness.commit(generation: 1, value: "retry")
            XCTAssertEqual(
                try harness.store.load(context: harness.context),
                .record(DurableStateRecord(generation: 1, plaintext: Data("retry".utf8))))
        }

        let harness = try Harness(faultPoint: .afterAnchorUpdate)
        XCTAssertThrowsError(try harness.commit(generation: 1, value: "new")) { error in
            XCTAssertEqual(error as? DurableStateStoreError, .interruptedWrite(.afterAnchorUpdate))
        }
        XCTAssertEqual(
            try harness.store.load(context: harness.context),
            .record(DurableStateRecord(generation: 1, plaintext: Data("new".utf8))))
    }

    func testKeyPlusSlotWithoutAnchorIsNotTreatedAsFirstRun() throws {
        let harness = try Harness(faultPoint: .afterRename)
        XCTAssertThrowsError(try harness.commit(generation: 1, value: "unanchored")) { error in
            XCTAssertEqual(error as? DurableStateStoreError, .interruptedWrite(.afterRename))
        }
        // A genuine first-commit interruption has a genesis anchor and safely loads empty.
        XCTAssertEqual(try harness.store.load(context: harness.context), .empty)

        harness.metadata.anchor = nil
        XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
            XCTAssertEqual(error as? DurableStateStoreError, .missingAnchor)
        }
    }

    func testFilesystemInvokesCompleteProtectionAndBackupExclusionPolicyHooks() throws {
        let harness = try Harness()
        try harness.commit(generation: 1, value: "protected")

        XCTAssertTrue(
            harness.securityPolicy.applications.contains {
                $0.url == harness.root.standardizedFileURL && $0.isDirectory
            })
        XCTAssertTrue(
            harness.securityPolicy.applications.contains {
                $0.url.lastPathComponent == "journal.lock" && !$0.isDirectory
            })
        XCTAssertTrue(
            harness.securityPolicy.applications.contains {
                $0.url.pathExtension == "tmp" && !$0.isDirectory
            })
        XCTAssertTrue(
            harness.securityPolicy.applications.contains {
                $0.url.lastPathComponent == "slot-a.bin" && !$0.isDirectory
            })

        let directoryAttributes = AppleCompleteFileSecurityPolicy.attributes(isDirectory: true)
        let fileAttributes = AppleCompleteFileSecurityPolicy.attributes(isDirectory: false)
        XCTAssertEqual(
            directoryAttributes[.protectionKey] as? FileProtectionType,
            FileProtectionType.complete)
        XCTAssertEqual(directoryAttributes[.posixPermissions] as? Int, 0o700)
        XCTAssertEqual(
            fileAttributes[.protectionKey] as? FileProtectionType,
            FileProtectionType.complete)
        XCTAssertEqual(fileAttributes[.posixPermissions] as? Int, 0o600)
        XCTAssertTrue(AppleCompleteFileSecurityPolicy.excludesFromBackup)
    }

    func testStateRootParentIsDurableBeforeGenesisAnchorCreation() throws {
        let harness = try Harness()
        let observer = harness.directorySyncObserver
        let expectedParent = harness.root.standardizedFileURL.deletingLastPathComponent()
        var checkedAtGenesis = false
        harness.metadata.onCreateAnchor = {
            checkedAtGenesis = true
            XCTAssertTrue(
                observer.directories.contains(expectedParent),
                "the root's parent entry must be fsynced before genesis anchoring")
        }

        try harness.commit(generation: 1, value: "durably-rooted")
        XCTAssertTrue(checkedAtGenesis)
    }

    func testBoundedStaleTemporarySlotIsRemovedUnderTheCommitLock() throws {
        let harness = try Harness()
        let staleTemporary = harness.root.appendingPathComponent(".slot-a.tmp")
        try Data("partial crash debris".utf8).write(to: staleTemporary)

        try harness.commit(generation: 1, value: "committed")

        XCTAssertFalse(FileManager.default.fileExists(atPath: staleTemporary.path))
        XCTAssertEqual(
            try harness.store.load(context: harness.context),
            .record(
                DurableStateRecord(
                    generation: 1,
                    plaintext: Data("committed".utf8))))
    }

    func testHostileFifoAndHardlinkedJournalLocksAreRejectedBeforePolicyMutation() throws {
        do {
            let harness = try Harness()
            let lockURL = harness.root.appendingPathComponent("journal.lock")
            XCTAssertEqual(Darwin.mkfifo(lockURL.path, mode_t(S_IRUSR | S_IWUSR)), 0)
            let policyCalls = harness.securityPolicy.applications.count

            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                assertStoragePolicyFailure(error)
            }
            XCTAssertEqual(harness.securityPolicy.applications.count, policyCalls)
        }

        do {
            let harness = try Harness()
            let victimURL = harness.root.appendingPathComponent("unrelated.txt")
            let lockURL = harness.root.appendingPathComponent("journal.lock")
            let victim = Data("must remain untouched".utf8)
            try victim.write(to: victimURL)
            XCTAssertEqual(Darwin.link(victimURL.path, lockURL.path), 0)
            let policyCalls = harness.securityPolicy.applications.count

            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                assertStoragePolicyFailure(error)
            }
            XCTAssertEqual(harness.securityPolicy.applications.count, policyCalls)
            XCTAssertEqual(try Data(contentsOf: victimURL), victim)
        }
    }

    func testApplicationOwnedParentSymlinkCannotRedirectStateRoot() throws {
        let container = FileManager.default.temporaryDirectory
            .appendingPathComponent("EUWallet-PathWalk-\(UUID().uuidString)", isDirectory: true)
        let trusted = container.appendingPathComponent("trusted", isDirectory: true)
        let redirectTarget = container.appendingPathComponent("redirect-target", isDirectory: true)
        try FileManager.default.createDirectory(at: trusted, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: redirectTarget, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: container) }
        try FileManager.default.createSymbolicLink(
            at: trusted.appendingPathComponent("redirect"),
            withDestinationURL: redirectTarget)

        XCTAssertThrowsError(
            try AppleDurableStateFileSystem(
                rootURL:
                    trusted
                    .appendingPathComponent("redirect", isDirectory: true)
                    .appendingPathComponent("state", isDirectory: true),
                trustedAncestorURL: trusted,
                securityPolicy: RecordingSecurityPolicy())
        ) { error in
            assertStoragePolicyFailure(error)
        }
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: redirectTarget.appendingPathComponent("state").path))
    }

    func testNewJournalLockEntryIsDurableBeforeUse() throws {
        let harness = try Harness()
        harness.directorySyncObserver.reset()

        XCTAssertEqual(try harness.store.load(context: harness.context), .empty)

        XCTAssertTrue(
            harness.directorySyncObserver.directories.contains(harness.root.standardizedFileURL),
            "creating the advisory lock must fsync its containing state directory")
    }

    func testKeychainCreationRequestsThisDeviceOnlyAccessibilityAndReplacementUsesUpdate() throws {
        let keychain = RecordingKeychain()
        let metadata = AppleKeychainDurableMetadataStore(
            service: "de.example.wallet.persistence",
            keychain: keychain,
            randomBytes: { Data(repeating: 0x55, count: $0) })

        XCTAssertEqual(try metadata.createInstallationKey(), Data(repeating: 0x55, count: 32))
        try metadata.createAnchor(Data("genesis".utf8))
        try metadata.replaceAnchor(Data("generation-one".utf8))

        XCTAssertEqual(keychain.added.count, 2)
        for attributes in keychain.added {
            XCTAssertEqual(
                attributes[kSecAttrAccessible as String] as? String,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        }
        XCTAssertEqual(keychain.updated.count, 1)
        XCTAssertEqual(
            keychain.updated[0].attributes[kSecValueData as String] as? Data,
            Data("generation-one".utf8))
        XCTAssertEqual(
            keychain.values[AppleKeychainDurableMetadataStore.anchorAccount],
            Data("generation-one".utf8))

        keychain.nextUpdateStatus = errSecNotAvailable
        XCTAssertThrowsError(try metadata.replaceAnchor(Data("must-not-land".utf8))) { error in
            XCTAssertEqual(
                error as? DurableStateStoreError,
                .secureMetadataFailure(
                    operation: "replace generation anchor",
                    status: errSecNotAvailable))
        }
        XCTAssertEqual(keychain.added.count, 2, "replacement must never delete and add")
        XCTAssertEqual(
            keychain.values[AppleKeychainDurableMetadataStore.anchorAccount],
            Data("generation-one".utf8),
            "failed SecItemUpdate must retain the previous anchor")
    }

    func testExistingOrMalformedInstallationKeyIsNeverSilentlyRegenerated() throws {
        do {
            let keychain = RecordingKeychain()
            keychain.values[AppleKeychainDurableMetadataStore.keyAccount] = Data(
                repeating: 0x11, count: 32)
            keychain.nextAddStatus = errSecDuplicateItem
            let metadata = AppleKeychainDurableMetadataStore(
                service: "de.example.wallet.persistence",
                keychain: keychain,
                randomBytes: { Data(repeating: 0x22, count: $0) })
            XCTAssertEqual(
                try metadata.createInstallationKey(),
                Data(repeating: 0x11, count: 32))
        }

        do {
            let harness = try Harness()
            harness.metadata.key = Data(repeating: 0, count: 31)
            XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
                XCTAssertEqual(error as? DurableStateStoreError, .corruptInstallationKey)
            }
            XCTAssertEqual(harness.metadata.createKeyCalls, 0)
        }
    }

    private func assertEnvelopeMutationRejected(
        expected: DurableStateStoreError,
        mutation: (inout Data) -> Void
    ) throws {
        let harness = try Harness()
        try harness.commit(generation: 1, value: "nonempty ciphertext")
        try harness.mutateAnchoredEnvelope(updateDigest: true, mutation)
        XCTAssertThrowsError(try harness.store.load(context: harness.context)) { error in
            XCTAssertEqual(error as? DurableStateStoreError, expected)
        }
    }

    private func assertStoragePolicyFailure(
        _ error: Error,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard let typed = error as? DurableStateStoreError,
            case .storagePolicyFailure = typed
        else {
            XCTFail("expected storagePolicyFailure, got \(error)", file: file, line: line)
            return
        }
    }
}

private enum AnchorOffset {
    static let formatVersion = 8
    static let schema = 10
    static let slot = 22
    static let applicationDigest = 23
    static let contextDigest = 55
    static let envelopeDigest = 87
}

private enum EnvelopeOffset {
    static let formatVersion = 8
    static let schema = 10
    static let generation = 14
    static let slot = 22
    static let nonceLength = 23
    static let ciphertextLength = 24
    static let nonce = 28
    static let ciphertext = 40
}

private final class Harness {
    let root: URL
    let metadata = TestMetadataStore()
    let securityPolicy = RecordingSecurityPolicy()
    let directorySyncObserver = RecordingDirectorySyncObserver()
    let faultInjector = OneShotFaultInjector()
    let fileSystem: AppleDurableStateFileSystem
    let context: DurableStateContext
    let store: AppleDurableStateStore

    init(faultPoint: DurableStateFaultPoint? = nil) throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("EUWallet-DurableState-\(UUID().uuidString)", isDirectory: true)
        context = try DurableStateContext(binding: Data("device-key:test-profile".utf8))
        if let faultPoint { faultInjector.arm(faultPoint) }
        fileSystem = try AppleDurableStateFileSystem(
            rootURL: root,
            securityPolicy: securityPolicy,
            directorySyncObserver: directorySyncObserver)
        store = try AppleDurableStateStore(
            applicationIdentifier: "de.example.euwallet",
            metadata: metadata,
            fileSystem: fileSystem,
            faultInjector: faultInjector)
    }

    deinit { try? FileManager.default.removeItem(at: root) }

    @discardableResult
    func commit(generation: UInt64, value: String) throws -> DurableStateRecord {
        try store.commit(
            expectedGeneration: generation - 1,
            nextGeneration: generation,
            plaintext: Data(value.utf8),
            context: context)
    }

    func mutateAnchoredEnvelope(
        updateDigest: Bool,
        _ mutation: (inout Data) -> Void
    ) throws {
        var envelope = try anchoredEnvelope()
        mutation(&envelope)
        try replaceAnchoredEnvelope(envelope, updateDigest: updateDigest)
    }

    func replaceAnchoredEnvelope(_ envelope: Data, updateDigest: Bool) throws {
        let slot = try anchoredSlot()
        try envelope.write(to: fileSystem.slotURL(slot), options: [])
        if updateDigest {
            var anchor = try XCTUnwrap(metadata.anchor)
            let digest = Data(SHA256.hash(data: envelope))
            anchor.replaceSubrange(
                AnchorOffset.envelopeDigest..<(AnchorOffset.envelopeDigest + 32),
                with: digest)
            metadata.anchor = anchor
        }
    }

    private func anchoredEnvelope() throws -> Data {
        try Data(contentsOf: fileSystem.slotURL(try anchoredSlot()))
    }

    private func anchoredSlot() throws -> DurableStateSlot {
        let anchor = try XCTUnwrap(metadata.anchor)
        return try XCTUnwrap(DurableStateSlot(rawValue: anchor[AnchorOffset.slot]))
    }
}

private final class TestMetadataStore: DurableSecureMetadataStore {
    var key: Data?
    var anchor: Data?
    private(set) var createKeyCalls = 0
    private(set) var createAnchorCalls = 0
    private(set) var replaceAnchorCalls = 0
    var onCreateAnchor: (() -> Void)?
    var failNextReplace = false

    func readInstallationKey() throws -> Data? { key }

    func createInstallationKey() throws -> Data {
        createKeyCalls += 1
        if let key { return key }
        let created = Data(repeating: 0x42, count: 32)
        key = created
        return created
    }

    func readAnchor() throws -> Data? { anchor }

    func createAnchor(_ value: Data) throws {
        createAnchorCalls += 1
        onCreateAnchor?()
        guard anchor == nil else { throw DurableStateStoreError.anchorAlreadyExists }
        anchor = value
    }

    func replaceAnchor(_ value: Data) throws {
        replaceAnchorCalls += 1
        if failNextReplace {
            failNextReplace = false
            throw DurableStateStoreError.secureMetadataFailure(
                operation: "test anchor update", status: -1)
        }
        guard anchor != nil else { throw DurableStateStoreError.missingAnchor }
        anchor = value
    }
}

private final class RecordingDirectorySyncObserver: DurableDirectorySyncObserving {
    private(set) var directories: [URL] = []

    func didSynchronizeDirectory(_ url: URL) {
        directories.append(url.standardizedFileURL)
    }

    func reset() { directories.removeAll() }
}

private final class OneShotFaultInjector: DurableStateFaultInjecting {
    private var point: DurableStateFaultPoint?
    private var fired = false

    func arm(_ point: DurableStateFaultPoint) {
        self.point = point
        fired = false
    }

    func hit(_ point: DurableStateFaultPoint) throws {
        guard self.point == point, !fired else { return }
        fired = true
        throw DurableStateStoreError.interruptedWrite(point)
    }
}

private final class RecordingSecurityPolicy: DurableFileSecurityPolicyApplying {
    struct Application {
        let url: URL
        let isDirectory: Bool
    }

    private(set) var applications: [Application] = []

    func apply(to url: URL, isDirectory: Bool) throws {
        applications.append(Application(url: url.standardizedFileURL, isDirectory: isDirectory))
    }
}

private final class RecordingKeychain: DurableKeychainAccessing {
    struct Update {
        let query: [String: Any]
        let attributes: [String: Any]
    }

    var values: [String: Data] = [:]
    var nextAddStatus: OSStatus?
    var nextUpdateStatus: OSStatus?
    private(set) var added: [[String: Any]] = []
    private(set) var updated: [Update] = []

    func copyMatching(_ query: [String: Any]) -> (OSStatus, Data?) {
        guard let account = query[kSecAttrAccount as String] as? String,
            let value = values[account]
        else {
            return (errSecItemNotFound, nil)
        }
        return (errSecSuccess, value)
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        added.append(attributes)
        if let status = nextAddStatus {
            nextAddStatus = nil
            return status
        }
        guard let account = attributes[kSecAttrAccount as String] as? String,
            let value = attributes[kSecValueData as String] as? Data
        else {
            return errSecParam
        }
        if values[account] != nil { return errSecDuplicateItem }
        values[account] = value
        return errSecSuccess
    }

    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        updated.append(Update(query: query, attributes: attributes))
        if let status = nextUpdateStatus {
            nextUpdateStatus = nil
            return status
        }
        guard let account = query[kSecAttrAccount as String] as? String,
            values[account] != nil,
            let value = attributes[kSecValueData as String] as? Data
        else {
            return errSecItemNotFound
        }
        values[account] = value
        return errSecSuccess
    }
}

private func setUInt16(_ value: UInt16, in data: inout Data, at offset: Int) {
    data[offset] = UInt8(truncatingIfNeeded: value >> 8)
    data[offset + 1] = UInt8(truncatingIfNeeded: value)
}

private func setUInt32(_ value: UInt32, in data: inout Data, at offset: Int) {
    for index in 0..<4 {
        data[offset + index] = UInt8(truncatingIfNeeded: value >> UInt32((3 - index) * 8))
    }
}

private func setUInt64(_ value: UInt64, in data: inout Data, at offset: Int) {
    for index in 0..<8 {
        data[offset + index] = UInt8(truncatingIfNeeded: value >> UInt64((7 - index) * 8))
    }
}
