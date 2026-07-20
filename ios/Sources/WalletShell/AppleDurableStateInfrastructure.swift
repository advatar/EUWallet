import Darwin
import Foundation
import Security

protocol DurableKeychainAccessing: AnyObject {
    func copyMatching(_ query: [String: Any]) -> (OSStatus, Data?)
    func add(_ attributes: [String: Any]) -> OSStatus
    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus
}

private final class SecurityDurableKeychainClient: DurableKeychainAccessing {
    func copyMatching(_ query: [String: Any]) -> (OSStatus, Data?) {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return (status, item as? Data)
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        SecItemAdd(attributes as CFDictionary, nil)
    }

    func update(_ query: [String: Any], attributes: [String: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }
}

final class AppleKeychainDurableMetadataStore: DurableSecureMetadataStore {
    static let keyAccount = "installation-key-v1"
    static let anchorAccount = "generation-anchor-v1"

    private let service: String
    private let keychain: any DurableKeychainAccessing
    private let randomBytes: (Int) throws -> Data

    convenience init(service: String) {
        self.init(
            service: service,
            keychain: SecurityDurableKeychainClient(),
            randomBytes: Self.secureRandomBytes)
    }

    init(
        service: String,
        keychain: any DurableKeychainAccessing,
        randomBytes: @escaping (Int) throws -> Data
    ) {
        self.service = service
        self.keychain = keychain
        self.randomBytes = randomBytes
    }

    func readInstallationKey() throws -> Data? {
        try read(account: Self.keyAccount, operation: "read installation key")
    }

    func createInstallationKey() throws -> Data {
        let candidate = try randomBytes(32)
        guard candidate.count == 32 else { throw DurableStateStoreError.corruptInstallationKey }
        let status = keychain.add(
            Self.addQuery(
                service: service,
                account: Self.keyAccount,
                value: candidate))
        if status == errSecSuccess { return candidate }
        if status == errSecDuplicateItem {
            guard let existing = try readInstallationKey() else {
                throw DurableStateStoreError.secureMetadataFailure(
                    operation: "recover concurrently-created installation key",
                    status: status)
            }
            guard existing.count == 32 else {
                throw DurableStateStoreError.corruptInstallationKey
            }
            return existing
        }
        throw DurableStateStoreError.secureMetadataFailure(
            operation: "create installation key", status: status)
    }

    func readAnchor() throws -> Data? {
        try read(account: Self.anchorAccount, operation: "read generation anchor")
    }

    func createAnchor(_ value: Data) throws {
        let status = keychain.add(
            Self.addQuery(
                service: service,
                account: Self.anchorAccount,
                value: value))
        if status == errSecDuplicateItem { throw DurableStateStoreError.anchorAlreadyExists }
        guard status == errSecSuccess else {
            throw DurableStateStoreError.secureMetadataFailure(
                operation: "create generation anchor", status: status)
        }
    }

    func replaceAnchor(_ value: Data) throws {
        // Deliberately update in place: delete-then-add creates a crash window with no anchor.
        let status = keychain.update(
            Self.itemQuery(service: service, account: Self.anchorAccount),
            attributes: [kSecValueData as String: value])
        if status == errSecItemNotFound { throw DurableStateStoreError.missingAnchor }
        guard status == errSecSuccess else {
            throw DurableStateStoreError.secureMetadataFailure(
                operation: "replace generation anchor", status: status)
        }
    }

    static func addQuery(service: String, account: String, value: Data) -> [String: Any] {
        var query = itemQuery(service: service, account: account)
        query[kSecValueData as String] = value
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        return query
    }

    static func itemQuery(service: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
        ]
    }

    private func read(account: String, operation: String) throws -> Data? {
        var query = Self.itemQuery(service: service, account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let (status, data) = keychain.copyMatching(query)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data else {
            throw DurableStateStoreError.secureMetadataFailure(
                operation: operation, status: status)
        }
        return data
    }

    private static func secureRandomBytes(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer -> OSStatus in
            guard let address = buffer.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, address)
        }
        guard status == errSecSuccess else {
            throw DurableStateStoreError.secureMetadataFailure(
                operation: "generate installation key", status: status)
        }
        return data
    }
}

protocol DurableFileSecurityPolicyApplying: AnyObject {
    func apply(to url: URL, isDirectory: Bool) throws
}

protocol DurableDirectorySyncObserving: AnyObject {
    func didSynchronizeDirectory(_ url: URL)
}

final class AppleCompleteFileSecurityPolicy: DurableFileSecurityPolicyApplying {
    static let excludesFromBackup = true

    static func attributes(isDirectory: Bool) -> [FileAttributeKey: Any] {
        [
            .protectionKey: FileProtectionType.complete,
            .posixPermissions: isDirectory ? 0o700 : 0o600,
        ]
    }

    func apply(to url: URL, isDirectory: Bool) throws {
        do {
            try FileManager.default.setAttributes(
                Self.attributes(isDirectory: isDirectory),
                ofItemAtPath: url.path)
            var protectedURL = url
            var values = URLResourceValues()
            values.isExcludedFromBackup = Self.excludesFromBackup
            try protectedURL.setResourceValues(values)
        } catch {
            throw DurableStateStoreError.storagePolicyFailure(String(describing: error))
        }
    }
}

final class AppleDurableStateFileSystem: DurableStateFileSystem {
    let rootURL: URL

    private let securityPolicy: any DurableFileSecurityPolicyApplying
    private let directorySyncObserver: (any DurableDirectorySyncObserving)?
    // `lockf`/fcntl locks coordinate other processes, while this process-wide lock also
    // serializes distinct store instances in the same application process.
    private static let processLock = NSLock()
    private var lockDescriptor: Int32?

    static func production(applicationIdentifier: String) throws -> AppleDurableStateFileSystem {
        let applicationSupport: URL
        do {
            applicationSupport = try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: false)
        } catch {
            throw DurableStateStoreError.storagePolicyFailure(String(describing: error))
        }
        let root =
            applicationSupport
            .appendingPathComponent(applicationIdentifier, isDirectory: true)
            .appendingPathComponent("EUWallet", isDirectory: true)
            .appendingPathComponent("DurableState-v1", isDirectory: true)
        return try AppleDurableStateFileSystem(
            rootURL: root,
            trustedAncestorURL: applicationSupport.deletingLastPathComponent(),
            securityPolicy: AppleCompleteFileSecurityPolicy())
    }

    init(
        rootURL: URL,
        trustedAncestorURL: URL? = nil,
        securityPolicy: any DurableFileSecurityPolicyApplying,
        directorySyncObserver: (any DurableDirectorySyncObserving)? = nil
    ) throws {
        self.rootURL = rootURL.standardizedFileURL
        self.securityPolicy = securityPolicy
        self.directorySyncObserver = directorySyncObserver
        do {
            try Self.createDirectoryDurably(
                self.rootURL,
                trustedAncestorURL: (trustedAncestorURL
                    ?? rootURL.deletingLastPathComponent()).standardizedFileURL,
                observer: directorySyncObserver)
            try securityPolicy.apply(to: self.rootURL, isDirectory: true)
            try Self.synchronizeDirectory(self.rootURL, observer: directorySyncObserver)
        } catch let error as DurableStateStoreError {
            throw error
        } catch {
            throw DurableStateStoreError.storagePolicyFailure(String(describing: error))
        }
    }

    deinit {
        if let descriptor = lockDescriptor {
            _ = Darwin.lockf(descriptor, F_ULOCK, 0)
            _ = Darwin.close(descriptor)
        }
    }

    func acquireExclusiveLock() throws {
        Self.processLock.lock()
        do {
            let lockURL = rootURL.appendingPathComponent("journal.lock", isDirectory: false)
            let (descriptor, created) = try Self.openValidatedLockFile(lockURL)
            do {
                try securityPolicy.apply(to: lockURL, isDirectory: false)
                try Self.requireValidLockDescriptor(descriptor)
                guard Darwin.fsync(descriptor) == 0 else {
                    throw Self.posixError("fsync lock")
                }
                if created {
                    // The lock is advisory and carries no wallet data, but making its directory
                    // entry durable avoids lock-inode divergence between racing processes after a
                    // crash.
                    try synchronizeDirectory()
                }
                while Darwin.lockf(descriptor, F_LOCK, 0) != 0 {
                    if errno == EINTR { continue }
                    throw Self.posixError("lockf")
                }
            } catch {
                _ = Darwin.close(descriptor)
                throw error
            }
            lockDescriptor = descriptor
        } catch {
            Self.processLock.unlock()
            throw error
        }
    }

    func releaseExclusiveLock() {
        if let descriptor = lockDescriptor {
            _ = Darwin.lockf(descriptor, F_ULOCK, 0)
            _ = Darwin.close(descriptor)
            lockDescriptor = nil
        }
        Self.processLock.unlock()
    }

    func hasAnySlot() throws -> Bool {
        try pathExists(slotURL(.a)) || pathExists(slotURL(.b))
    }

    func read(slot: DurableStateSlot, maximumBytes: Int) throws -> Data? {
        let url = slotURL(slot)
        let descriptor = Darwin.open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        if descriptor < 0 {
            if errno == ENOENT { return nil }
            throw Self.posixError("open slot")
        }
        defer { _ = Darwin.close(descriptor) }

        var status = stat()
        guard Darwin.fstat(descriptor, &status) == 0 else {
            throw Self.posixError("fstat slot")
        }
        guard (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG), status.st_nlink == 1 else {
            throw DurableStateStoreError.storagePolicyFailure(
                "durable-state slot is not a singly-linked regular file")
        }
        guard status.st_size >= 0 else { throw DurableStateStoreError.corruptEnvelope }
        if status.st_size > off_t(maximumBytes) {
            let actual = status.st_size > off_t(Int.max) ? Int.max : Int(status.st_size)
            throw DurableStateStoreError.envelopeTooLarge(
                actual: actual, maximum: maximumBytes)
        }

        var data = Data()
        data.reserveCapacity(Int(status.st_size))
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let count = Darwin.read(descriptor, &buffer, buffer.count)
            if count == 0 { break }
            if count < 0 {
                if errno == EINTR { continue }
                throw Self.posixError("read slot")
            }
            guard data.count <= maximumBytes - count else {
                throw DurableStateStoreError.envelopeTooLarge(
                    actual: data.count + count, maximum: maximumBytes)
            }
            data.append(contentsOf: buffer[0..<count])
        }
        guard data.count == Int(status.st_size) else {
            throw DurableStateStoreError.corruptEnvelope
        }
        return data
    }

    func writeDurably(
        _ data: Data,
        to slot: DurableStateSlot,
        faultInjector: (any DurableStateFaultInjecting)?
    ) throws {
        try faultInjector?.hit(.beforeTemporaryCreate)
        let temporaryURL = rootURL.appendingPathComponent(
            slot == .a ? ".slot-a.tmp" : ".slot-b.tmp",
            isDirectory: false)
        // A deterministic, store-owned temporary name prevents crash debris from accumulating.
        // The process/file lock makes removal safe, and unlinking never follows a hostile symlink.
        if Darwin.unlink(temporaryURL.path) != 0, errno != ENOENT {
            throw Self.posixError("remove stale temporary slot")
        }
        var descriptor = Darwin.open(
            temporaryURL.path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            mode_t(S_IRUSR | S_IWUSR))
        guard descriptor >= 0 else { throw Self.posixError("create temporary slot") }
        defer {
            if descriptor >= 0 { _ = Darwin.close(descriptor) }
            _ = Darwin.unlink(temporaryURL.path)
        }

        try securityPolicy.apply(to: temporaryURL, isDirectory: false)
        try faultInjector?.hit(.afterTemporaryCreate)
        try Self.writeAll(data, descriptor: descriptor)
        try faultInjector?.hit(.afterTemporaryWrite)
        guard Darwin.fsync(descriptor) == 0 else { throw Self.posixError("fsync slot") }
        try faultInjector?.hit(.afterTemporarySync)
        guard Darwin.close(descriptor) == 0 else { throw Self.posixError("close slot") }
        descriptor = -1

        let destination = slotURL(slot)
        guard Darwin.rename(temporaryURL.path, destination.path) == 0 else {
            throw Self.posixError("rename slot")
        }
        // Rename preserves the temporary file's protection; applying again verifies the final path
        // and keeps the policy observable in assurance tests.
        try securityPolicy.apply(to: destination, isDirectory: false)
        try faultInjector?.hit(.afterRename)
        try synchronizeDirectory()
        try faultInjector?.hit(.afterDirectorySync)
    }

    func slotURL(_ slot: DurableStateSlot) -> URL {
        rootURL.appendingPathComponent(
            slot == .a ? "slot-a.bin" : "slot-b.bin",
            isDirectory: false)
    }

    private func pathExists(_ url: URL) throws -> Bool {
        var status = stat()
        if Darwin.lstat(url.path, &status) == 0 { return true }
        if errno == ENOENT { return false }
        throw Self.posixError("lstat slot")
    }

    private func synchronizeDirectory() throws {
        try Self.synchronizeDirectory(rootURL, observer: directorySyncObserver)
    }

    private static func createDirectoryDurably(
        _ rootURL: URL,
        trustedAncestorURL: URL,
        observer: (any DurableDirectorySyncObserving)?
    ) throws {
        let rootComponents = rootURL.pathComponents
        let ancestorComponents = trustedAncestorURL.pathComponents
        guard rootComponents.count > ancestorComponents.count,
            Array(rootComponents.prefix(ancestorComponents.count)) == ancestorComponents
        else {
            throw DurableStateStoreError.storagePolicyFailure(
                "durable-state root is outside its trusted application ancestor")
        }
        let relativeComponents = Array(rootComponents.dropFirst(ancestorComponents.count))
        guard relativeComponents.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else {
            throw DurableStateStoreError.storagePolicyFailure(
                "durable-state path contains an invalid component")
        }

        var parentDescriptor = Darwin.open(
            trustedAncestorURL.path,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard parentDescriptor >= 0 else {
            throw DurableStateStoreError.storagePolicyFailure(
                "trusted durable-state ancestor is missing, a symlink, or not a directory")
        }
        defer {
            if parentDescriptor >= 0 { _ = Darwin.close(parentDescriptor) }
        }
        try requireOwnedDirectoryDescriptor(parentDescriptor)

        var parentURL = trustedAncestorURL
        for (index, component) in relativeComponents.enumerated() {
            let (childDescriptor, created) = try openOrCreateDirectory(
                parentDescriptor: parentDescriptor,
                component: component)
            if created || index == relativeComponents.count - 1 {
                // Persist each newly-created path component, and always prove the final root entry
                // durable before a Keychain anchor can refer to a slot below it.
                try synchronizeDirectoryDescriptor(
                    parentDescriptor,
                    url: parentURL,
                    observer: observer)
            }
            _ = Darwin.close(parentDescriptor)
            parentDescriptor = childDescriptor
            parentURL.appendPathComponent(component, isDirectory: true)
        }
    }

    private static func openOrCreateDirectory(
        parentDescriptor: Int32,
        component: String
    ) throws -> (Int32, Bool) {
        let flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        var descriptor = component.withCString {
            Darwin.openat(parentDescriptor, $0, flags)
        }
        if descriptor >= 0 {
            try requireOwnedDirectoryDescriptor(descriptor)
            return (descriptor, false)
        }
        guard errno == ENOENT else {
            if errno == ELOOP || errno == ENOTDIR {
                throw DurableStateStoreError.storagePolicyFailure(
                    "durable-state path contains a symlink or non-directory component")
            }
            throw posixError("open state directory component")
        }

        let createResult = component.withCString {
            Darwin.mkdirat(parentDescriptor, $0, mode_t(S_IRWXU))
        }
        if createResult != 0, errno != EEXIST {
            throw posixError("create state directory component")
        }
        descriptor = component.withCString {
            Darwin.openat(parentDescriptor, $0, flags)
        }
        guard descriptor >= 0 else {
            if errno == ELOOP || errno == ENOTDIR {
                throw DurableStateStoreError.storagePolicyFailure(
                    "new durable-state path component was replaced by a symlink")
            }
            throw posixError("open created state directory component")
        }
        do {
            try requireOwnedDirectoryDescriptor(descriptor)
        } catch {
            _ = Darwin.close(descriptor)
            throw error
        }
        return (descriptor, createResult == 0)
    }

    private static func requireOwnedDirectoryDescriptor(_ descriptor: Int32) throws {
        var status = stat()
        guard Darwin.fstat(descriptor, &status) == 0 else {
            throw posixError("fstat state directory")
        }
        guard (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFDIR),
            status.st_uid == Darwin.geteuid()
        else {
            throw DurableStateStoreError.storagePolicyFailure(
                "durable-state path is not an application-owned real directory")
        }
    }

    private static func synchronizeDirectoryDescriptor(
        _ descriptor: Int32,
        url: URL,
        observer: (any DurableDirectorySyncObserving)?
    ) throws {
        guard Darwin.fsync(descriptor) == 0 else {
            throw Self.posixError("fsync state directory")
        }
        observer?.didSynchronizeDirectory(url.standardizedFileURL)
    }

    private static func synchronizeDirectory(
        _ url: URL,
        observer: (any DurableDirectorySyncObserving)?
    ) throws {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        guard descriptor >= 0 else { throw Self.posixError("open state directory") }
        defer { _ = Darwin.close(descriptor) }
        guard Darwin.fsync(descriptor) == 0 else {
            throw Self.posixError("fsync state directory")
        }
        observer?.didSynchronizeDirectory(url.standardizedFileURL)
    }

    private static func openValidatedLockFile(_ url: URL) throws -> (Int32, Bool) {
        for _ in 0..<3 {
            var prior = stat()
            if Darwin.lstat(url.path, &prior) == 0 {
                try requireValidLockStatus(prior)
                let descriptor = Darwin.open(
                    url.path,
                    O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
                if descriptor < 0 {
                    if errno == ENOENT { continue }
                    throw posixError("open existing lock")
                }
                do {
                    var opened = stat()
                    guard Darwin.fstat(descriptor, &opened) == 0 else {
                        throw posixError("fstat lock")
                    }
                    try requireValidLockStatus(opened)
                    guard opened.st_dev == prior.st_dev, opened.st_ino == prior.st_ino else {
                        throw DurableStateStoreError.storagePolicyFailure(
                            "durable-state lock changed while opening")
                    }
                } catch {
                    _ = Darwin.close(descriptor)
                    throw error
                }
                return (descriptor, false)
            }
            guard errno == ENOENT else { throw posixError("lstat lock") }

            let descriptor = Darwin.open(
                url.path,
                O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
                mode_t(S_IRUSR | S_IWUSR))
            if descriptor < 0 {
                if errno == EEXIST { continue }
                throw posixError("create lock")
            }
            do {
                try requireValidLockDescriptor(descriptor)
            } catch {
                _ = Darwin.close(descriptor)
                throw error
            }
            return (descriptor, true)
        }
        throw DurableStateStoreError.storagePolicyFailure(
            "durable-state lock changed repeatedly while opening")
    }

    private static func requireValidLockDescriptor(_ descriptor: Int32) throws {
        var status = stat()
        guard Darwin.fstat(descriptor, &status) == 0 else {
            throw posixError("fstat lock")
        }
        try requireValidLockStatus(status)
    }

    private static func requireValidLockStatus(_ status: stat) throws {
        guard (status.st_mode & mode_t(S_IFMT)) == mode_t(S_IFREG),
            status.st_nlink == 1,
            status.st_uid == Darwin.geteuid(),
            status.st_size == 0
        else {
            throw DurableStateStoreError.storagePolicyFailure(
                "durable-state lock is not an empty, singly-linked, application-owned regular file")
        }
    }

    private static func writeAll(_ data: Data, descriptor: Int32) throws {
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                guard let base = bytes.baseAddress else { break }
                let count = Darwin.write(
                    descriptor,
                    base.advanced(by: offset),
                    bytes.count - offset)
                if count < 0 {
                    if errno == EINTR { continue }
                    throw posixError("write slot")
                }
                guard count > 0 else { throw posixError("write slot") }
                offset += count
            }
        }
    }

    private static func posixError(_ operation: String) -> DurableStateStoreError {
        DurableStateStoreError.storageFailure(operation: operation, code: errno)
    }
}
