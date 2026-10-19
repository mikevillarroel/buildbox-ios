import Foundation
import Security
import Compression
import CryptoKit

// MARK: - On-device IPA signing
// Implements ESign-style signing: unzip → update plist → inject provision → sign binaries → rezip

class IPASigner {
    static let shared = IPASigner()
    
    // MARK: - Main signing function
    func sign(ipaURL: URL, p12URL: URL, p12Password: String, provisionURL: URL,
              appName: String, bundleID: String, version: String,
              progress: @escaping (String) -> Void,
              completion: @escaping (Result<URL, Error>) -> Void) {
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                progress("Loading certificate...")
                let (identity, cert) = try self.loadIdentity(p12URL: p12URL, password: p12Password)

                // Resolve nested IPA (GitHub Actions wraps IPA in a ZIP)
                let resolvedIPA = self.resolveNestedIPA(ipaURL: ipaURL)

                progress("Unzipping IPA...")
                let workDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
                try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: workDir) }

                try self.unzip(ipaURL: resolvedIPA, to: workDir)
                
                // Find the .app bundle
                progress("Finding app bundle...")
                let payloadDir = workDir.appendingPathComponent("Payload")
                let appBundle = try self.findAppBundle(in: payloadDir)
                
                progress("Updating Info.plist...")
                try self.updateInfoPlist(appBundle: appBundle, appName: appName, bundleID: bundleID, version: version)
                
                progress("Injecting provisioning profile...")
                try self.injectProvision(appBundle: appBundle, provisionURL: provisionURL)
                
                progress("Signing binaries...")
                try self.signBinaries(appBundle: appBundle, identity: identity, cert: cert, provisionURL: provisionURL, bundleID: bundleID)

                progress("Generating CodeResources...")
                try self.generateCodeResources(appBundle: appBundle)

                progress("Repackaging IPA...")
                let outputURL = FileManager.default.temporaryDirectory
                    .appendingPathComponent("\(appName)_\(version)_signed.ipa")
                try? FileManager.default.removeItem(at: outputURL)
                try self.zip(sourceDir: workDir, to: outputURL)
                
                progress("Done!")
                DispatchQueue.main.async { completion(.success(outputURL)) }
            } catch {
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }
    
    // MARK: - ZSign-based signing (uses embedded zsign C++ library)
    func signWithZSign(ipaURL: URL, p12URL: URL, p12Password: String, provisionURL: URL,
                       appName: String, bundleID: String, version: String,
                       progress: @escaping (String) -> Void,
                       completion: @escaping (Result<URL, Error>) -> Void) {
        
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                // Resolve nested IPA (GitHub Actions wraps IPA in a ZIP)
                let resolvedIPA = self.resolveNestedIPA(ipaURL: ipaURL)

                progress("Unzipping IPA...")
                let workDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
                try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
                defer { try? FileManager.default.removeItem(at: workDir) }

                try self.unzip(ipaURL: resolvedIPA, to: workDir)
                
                // Find the .app bundle
                progress("Finding app bundle...")
                let payloadDir = workDir.appendingPathComponent("Payload")
                let appBundle = try self.findAppBundle(in: payloadDir)
                
                progress("Signing with zsign...")
                let signed = ZSign.sign(
                    appPath: appBundle.path,
                    provisionPath: provisionURL.path,
                    p12Path: p12URL.path,
                    p12Password: p12Password,
                    bundleID: bundleID,
                    displayName: appName,
                    version: version
                )
                
                guard signed else {
                    throw SignError.signingFailed("zsign returned false")
                }

                progress("Repackaging IPA...")
                let outputURL = FileManager.default.temporaryDirectory
                    .appendingPathComponent("\(appName)_\(version)_signed.ipa")
                try? FileManager.default.removeItem(at: outputURL)
                try self.zip(sourceDir: workDir, to: outputURL)
                
                progress("Done!")
                DispatchQueue.main.async { completion(.success(outputURL)) }
            } catch {
                DispatchQueue.main.async { completion(.failure(error)) }
            }
        }
    }
    
    // MARK: - Load P12 identity
    private func loadIdentity(p12URL: URL, password: String) throws -> (SecIdentity, SecCertificate) {
        guard let p12Data = try? Data(contentsOf: p12URL) else {
            throw SignError.certificateNotFound
        }
        let options: [String: Any] = [kSecImportExportPassphrase as String: password]
        var items: CFArray?
        let status = SecPKCS12Import(p12Data as CFData, options as CFDictionary, &items)
        guard status == errSecSuccess,
              let arr = items as? [[String: Any]],
              let dict = arr.first,
              let identityValue = dict[kSecImportItemIdentity as String],
              CFGetTypeID(identityValue as CFTypeRef) == SecIdentityGetTypeID() else {
            throw SignError.invalidPassword
        }
        let identity = identityValue as! SecIdentity
        var cert: SecCertificate?
        SecIdentityCopyCertificate(identity, &cert)
        guard let c = cert else { throw SignError.certificateNotFound }
        return (identity, c)
    }
    
    // MARK: - Find .app bundle
    private func findAppBundle(in payloadDir: URL) throws -> URL {
        let contents = try FileManager.default.contentsOfDirectory(at: payloadDir, includingPropertiesForKeys: nil)
        guard let app = contents.first(where: { $0.pathExtension == "app" }) else {
            throw SignError.appBundleNotFound
        }
        return app
    }
    
    // MARK: - Update Info.plist
    private func updateInfoPlist(appBundle: URL, appName: String, bundleID: String, version: String) throws {
        let plistURL = appBundle.appendingPathComponent("Info.plist")
        guard var plist = try? NSDictionary(contentsOf: plistURL, error: ()) as? [String: Any] else {
            // Try binary plist
            guard let data = try? Data(contentsOf: plistURL),
                  var p = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
                throw SignError.plistError
            }
            p["CFBundleName"] = appName
            p["CFBundleDisplayName"] = appName
            p["CFBundleIdentifier"] = bundleID
            p["CFBundleShortVersionString"] = version
            let newData = try PropertyListSerialization.data(fromPropertyList: p, format: .xml, options: 0)
            try newData.write(to: plistURL)
            return
        }
        plist["CFBundleName"] = appName
        plist["CFBundleDisplayName"] = appName
        plist["CFBundleIdentifier"] = bundleID
        plist["CFBundleShortVersionString"] = version
        let newData = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try newData.write(to: plistURL)
    }
    
    // MARK: - Inject provisioning profile
    private func injectProvision(appBundle: URL, provisionURL: URL) throws {
        let dest = appBundle.appendingPathComponent("embedded.mobileprovision")
        try? FileManager.default.removeItem(at: dest)
        try FileManager.default.copyItem(at: provisionURL, to: dest)
    }
    
    // MARK: - Sign binaries
    private func signBinaries(appBundle: URL, identity: SecIdentity, cert: SecCertificate, provisionURL: URL, bundleID: String) throws {
        // Find all Mach-O binaries (main executable + frameworks + appex)
        let binaries = try findBinaries(in: appBundle)
        for binary in binaries {
            try signBinary(at: binary, identity: identity, cert: cert, bundleID: bundleID, provisionURL: provisionURL)
        }
    }

    // MARK: - Generate CodeResources
    /// Creates _CodeSignature/CodeResources with SHA-1 + SHA-256 hashes of bundle resources.
    /// iOS requires this to verify bundle integrity during install.
    private func generateCodeResources(appBundle: URL) throws {
        let fm = FileManager.default
        let codeSigDir = appBundle.appendingPathComponent("_CodeSignature")
        try fm.createDirectory(at: codeSigDir, withIntermediateDirectories: true)

        // Files to exclude (standard codesign rules)
        let excludeNames: Set<String> = ["CodeResources", "CodeSignature", "CodeDirectory", "CodeRequirements"]

        var files2: [String: [String: Data]] = [:]

        let enumerator = fm.enumerator(at: appBundle, includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey])
        while let file = enumerator?.nextObject() as? URL {
            let vals = try? file.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey])
            guard vals?.isRegularFile == true else { continue }

            // Relative path from app bundle
            let relPath = file.path.replacingOccurrences(of: appBundle.path + "/", with: "")

            // Skip _CodeSignature contents (except we list them? No - exclude)
            if relPath.hasPrefix("_CodeSignature/") { continue }
            // Skip excluded names
            let fileName = file.lastPathComponent
            if excludeNames.contains(fileName) { continue }
            // Skip symlinks (we already filter to regular files)

            // Compute hashes
            guard let fileData = try? Data(contentsOf: file) else { continue }
            let sha1 = Data(Insecure.SHA1.hash(data: fileData))
            let sha256 = Data(SHA256.hash(data: fileData))

            files2[relPath] = ["hash": sha1, "hash2": sha256]
        }

        // Also include the main binary? No - binaries are signed via Mach-O, not CodeResources.
        // But Info.plist and embedded.mobileprovision MUST be here.

        // Build the plist
        // files2: [path: [hash: Data, hash2: Data]]
        // rules: standard exclusions
        let rules: [String: Any] = [
            "^_CodeSignature/": true,
            "^CodeResources$": true,
        ]

        // Convert files2 to plist-compatible format
        var files2Plist: [String: [String: Data]] = [:]
        for (path, hashes) in files2 {
            files2Plist[path] = hashes
        }

        let plist: [String: Any] = [
            "files2": files2Plist,
            "rules": rules,
            "rules2": [
                ".*\\.dSYM/": ["weight": 11.0],
                "^_CodeSignature/": ["omit": true, "weight": 20.0],
            ] as [String: [String: Any]]
        ]

        let plistData = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try plistData.write(to: codeSigDir.appendingPathComponent("CodeResources"))
    }
    
    private func findBinaries(in dir: URL) throws -> [URL] {
        var binaries: [URL] = []
        let enumerator = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: [.isRegularFileKey])
        while let file = enumerator?.nextObject() as? URL {
            // Check if it's a Mach-O binary (not a plist, not a resource)
            let ext = file.pathExtension
            if ext.isEmpty || ext == "dylib" {
                // Check magic number
                if let handle = try? FileHandle(forReadingFrom: file),
                   let magic = try? handle.read(upToCount: 4) {
                    try? handle.close()
                    // Mach-O magic: FE ED FA CE, FE ED FA CF, CA FE BA BE
                    // Also little-endian: CE FA ED FE, CF FA ED FE
                    if magic.count == 4 {
                        let b = [UInt8](magic)
                        if (b[0] == 0xFE && b[1] == 0xED && b[2] == 0xFA && (b[3] == 0xCE || b[3] == 0xCF)) ||
                           (b[0] == 0xCE && b[1] == 0xFA && b[2] == 0xED && b[3] == 0xFE) ||
                           (b[0] == 0xCF && b[1] == 0xFA && b[2] == 0xED && b[3] == 0xFE) ||
                           (b[0] == 0xCA && b[1] == 0xFE && b[2] == 0xBA && b[3] == 0xBE) {
                            binaries.append(file)
                        }
                    }
                }
            }
            // Frameworks
            if ext == "framework" {
                let name = file.deletingPathExtension().lastPathComponent
                let bin = file.appendingPathComponent(name)
                if FileManager.default.fileExists(atPath: bin.path) {
                    binaries.append(bin)
                }
            }
        }
        return binaries
    }
    
    private func signBinary(at url: URL, identity: SecIdentity, cert: SecCertificate, bundleID: String, provisionURL: URL) throws {
        // Real Mach-O code signing with two-pass for correct page hashes
        // Pass 1: Build signature to determine its size
        // Pass 2: Rebuild with correct LC_CODE_SIGNATURE datasize in hashes
        var data = try Data(contentsOf: url)

        // Step 1: Insert placeholder LC_CODE_SIGNATURE BEFORE hashing
        try MachOSigner.insertPlaceholderSignature(machoData: &data)

        // Helper to build the full signature blob (used in both passes)
        // CRITICAL: LC_CODE_SIGNATURE must be zeroed during page hash computation
        // (iOS excludes it from the hash verification)
        func buildSignatureBlob(for inputData: Data) throws -> Data {
            var hashData = inputData
            // Zero out LC_CODE_SIGNATURE command (16 bytes) before hashing
            let (_, cmds) = try MachOSigner.parseHeader(data: hashData)
            if let sigCmd = cmds.first(where: { $0.cmd == 0x1D }) {
                for i in 0..<16 {
                    if sigCmd.offset + i < hashData.count {
                        hashData[sigCmd.offset + i] = 0
                    }
                }
            }
            let codeSize = inputData.count
            let pageHashesSHA1 = MachOSigner.computePageHashes(data: hashData, codeOffset: 0, codeSize: codeSize, useSHA1: true)
            let pageHashesSHA256 = MachOSigner.computePageHashes(data: hashData, codeOffset: 0, codeSize: codeSize, useSHA1: false)

            guard let certData = SecCertificateCopyData(cert) as Data? else {
                throw SignError.certificateNotFound
            }
            let teamID = DER.extractTeamID(from: certData)

            let cdSHA1 = MachOSigner.buildCodeDirectory(identifier: bundleID, pageHashes: pageHashesSHA1, codeLimit: UInt64(codeSize), teamID: teamID, useSHA1: true)
            let cdSHA256 = MachOSigner.buildCodeDirectory(identifier: bundleID, pageHashes: pageHashesSHA256, codeLimit: UInt64(codeSize), teamID: teamID, useSHA1: false)

            let cmsSig = try MachOSigner.createCMSSignature(codeDirectory: cdSHA1, alternateCD: cdSHA256, identity: identity)
            let entitlements = MachOSigner.extractEntitlements(from: provisionURL)
            return MachOSigner.buildSuperBlob(codeDirectory: cdSHA1, alternateCD: cdSHA256, entitlements: entitlements, cmsSignature: cmsSig)
        }

        // Pass 1: Build with placeholder datasize=0 to get the signature size
        let pass1Blob = try buildSignatureBlob(for: data)
        let sigSize = pass1Blob.count

        // Update LC_CODE_SIGNATURE datasize in data (without appending blob yet)
        let (_, commands) = try MachOSigner.parseHeader(data: data)
        guard let sigCmd = commands.first(where: { $0.cmd == 0x1D }) else {
            throw SignError.corruptZip
        }
        // Patch datasize field (offset+12) in the data
        let ds = UInt32(sigSize)
        data[sigCmd.offset+12] = UInt8(ds & 0xFF)
        data[sigCmd.offset+13] = UInt8((ds >> 8) & 0xFF)
        data[sigCmd.offset+14] = UInt8((ds >> 16) & 0xFF)
        data[sigCmd.offset+15] = UInt8((ds >> 24) & 0xFF)

        // Pass 2: Rebuild with correct datasize in the hashes
        let pass2Blob = try buildSignatureBlob(for: data)

        // Sanity: sizes should match (if not, we'd need a third pass, but they should be stable)
        // Append and finalize
        try MachOSigner.finalizeSignature(machoData: &data, signature: pass2Blob)

        // Write back
        try data.write(to: url)
    }
    
    // MARK: - Read IPA metadata (name, bundle ID, version from Info.plist)
    // If the IPA is nested (a ZIP containing a single .ipa), extract the inner one
    func resolveNestedIPA(ipaURL: URL) -> URL {
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent("nested-\(UUID().uuidString)")
        do {
            try fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
            try self.unzip(ipaURL: ipaURL, to: tempDir)
            // Check for Payload folder (normal IPA)
            let payload = tempDir.appendingPathComponent("Payload")
            if fm.fileExists(atPath: payload.path) {
                try? fm.removeItem(at: tempDir)
                return ipaURL // Not nested, use original
            }
            // Look for a single .ipa file
            let contents = try fm.contentsOfDirectory(at: tempDir, includingPropertiesForKeys: nil)
            let ipaFiles = contents.filter { $0.pathExtension.lowercased() == "ipa" }
            if ipaFiles.count == 1, let inner = ipaFiles.first {
                // Copy to Documents so it persists
                let docs = fm.urls(for: .documentDirectory, in: .userDomainMask).first!
                let dest = docs.appendingPathComponent("inner-\(inner.lastPathComponent)")
                try? fm.removeItem(at: dest)
                try fm.copyItem(at: inner, to: dest)
                try? fm.removeItem(at: tempDir)
                return dest
            }
            try? fm.removeItem(at: tempDir)
        } catch {
            try? fm.removeItem(at: tempDir)
        }
        return ipaURL
    }

    func readMetadata(ipaURL: URL) -> (appName: String?, bundleID: String?, version: String?) {
        let resolved = resolveNestedIPA(ipaURL: ipaURL)
        // Try fast ZIP parsing first
        if let meta = readMetadataFast(ipaURL: resolved), meta.bundleID != nil {
            return meta
        }
        // Fallback: unzip to temp and read Info.plist directly (more robust)
        return readMetadataViaUnzip(ipaURL: ipaURL)
    }

    private func readMetadataViaUnzip(ipaURL: URL) -> (appName: String?, bundleID: String?, version: String?) {
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory.appendingPathComponent("readmeta-\(UUID().uuidString)")
        do {
            try fm.createDirectory(at: tempDir, withIntermediateDirectories: true)
            defer { try? fm.removeItem(at: tempDir) }
            try self.unzip(ipaURL: ipaURL, to: tempDir)
            let payloadDir = tempDir.appendingPathComponent("Payload")
            let appBundle = try self.findAppBundle(in: payloadDir)
            let plistURL = appBundle.appendingPathComponent("Info.plist")
            let plistData = try Data(contentsOf: plistURL)
            if let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any] {
                let appName = (plist["CFBundleDisplayName"] as? String) ?? (plist["CFBundleName"] as? String)
                let bundleID = plist["CFBundleIdentifier"] as? String
                let version = plist["CFBundleShortVersionString"] as? String
                return (appName, bundleID, version)
            }
        } catch {
            // Fall through to nils
        }
        return (nil, nil, nil)
    }

    private func readMetadataFast(ipaURL: URL) -> (appName: String?, bundleID: String?, version: String?)? {
        do {
            let data = try Data(contentsOf: ipaURL)
            let bytes = [UInt8](data)
            var offset = 0
            
            while offset + 30 < bytes.count {
                guard bytes[offset] == 0x50 && bytes[offset+1] == 0x4B &&
                      bytes[offset+2] == 0x03 && bytes[offset+3] == 0x04 else {
                    break
                }
                
                let method = UInt16(bytes[offset+8]) | (UInt16(bytes[offset+9]) << 8)
                let compSize = UInt32(bytes[offset+18]) | (UInt32(bytes[offset+19]) << 8) |
                              (UInt32(bytes[offset+20]) << 16) | (UInt32(bytes[offset+21]) << 24)
                let uncompSize = UInt32(bytes[offset+22]) | (UInt32(bytes[offset+23]) << 8) |
                                 (UInt32(bytes[offset+24]) << 16) | (UInt32(bytes[offset+25]) << 24)
                let nameLen = Int(UInt16(bytes[offset+26]) | (UInt16(bytes[offset+27]) << 8))
                let extraLen = Int(UInt16(bytes[offset+28]) | (UInt16(bytes[offset+29]) << 8))
                
                let nameStart = offset + 30
                let nameEnd = nameStart + nameLen
                guard nameEnd <= bytes.count else { break }
                
                let nameData = Data(bytes[nameStart..<nameEnd])
                guard let name = String(data: nameData, encoding: .utf8) else {
                    offset = nameEnd + extraLen + Int(compSize)
                    continue
                }
                
                // Look for Payload/*.app/Info.plist
                if name.hasPrefix("Payload/") && name.hasSuffix(".app/Info.plist") {
                    let dataStart = nameEnd + extraLen
                    let dataEnd = dataStart + Int(compSize)
                    guard dataEnd <= bytes.count else { break }
                    
                    let plistData: Data
                    if method == 0 {
                        plistData = Data(bytes[dataStart..<dataEnd])
                    } else if method == 8 {
                        let compData = Data(bytes[dataStart..<dataEnd])
                        plistData = try inflate(data: compData, expectedSize: Int(uncompSize))
                    } else {
                        break
                    }
                    
                    if let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any] {
                        let appName = (plist["CFBundleDisplayName"] as? String) ?? (plist["CFBundleName"] as? String)
                        let bundleID = plist["CFBundleIdentifier"] as? String
                        let version = plist["CFBundleShortVersionString"] as? String
                        return (appName, bundleID, version)
                    }
                    break
                }
                
                offset = nameEnd + extraLen + Int(compSize)
            }
        } catch {
            // Silently fail, return nils
        }
        return (nil, nil, nil)
    }
    
    // MARK: - ZIP utilities (minimal implementation)
    private func unzip(ipaURL: URL, to destDir: URL) throws {
        // Use Compression framework for deflate, manually parse ZIP structure
        let data = try Data(contentsOf: ipaURL)
        try unzipData(data, to: destDir)
    }
    
    private func unzipData(_ data: Data, to destDir: URL) throws {
        // Central-directory driven parser — handles data descriptors (general
        // purpose bit 3), which GitHub Actions artifact ZIPs use. Local-header
        // sizes are ignored; real sizes come from the central directory.
        let bytes = [UInt8](data)
        guard let entries = parseCentralDirectory(bytes), !entries.isEmpty else {
            throw SignError.corruptZip
        }
        for entry in entries {
            if entry.name.hasSuffix("/") { continue } // directory entry
            if entry.name.contains("..") { continue } // path traversal guard
            let lh = entry.localHeaderOffset
            guard lh + 30 <= bytes.count,
                  bytes[lh] == 0x50 && bytes[lh+1] == 0x4B &&
                  bytes[lh+2] == 0x03 && bytes[lh+3] == 0x04 else {
                throw SignError.corruptZip
            }
            let localNameLen = Int(readU16(bytes, lh + 26))
            let localExtraLen = Int(readU16(bytes, lh + 28))
            let dataStart = lh + 30 + localNameLen + localExtraLen
            let dataEnd = dataStart + Int(entry.compSize)
            guard dataStart <= bytes.count, dataEnd <= bytes.count else {
                throw SignError.corruptZip
            }

            let fileURL = destDir.appendingPathComponent(entry.name)
            try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(),
                                                   withIntermediateDirectories: true)
            let fileData: Data
            if entry.method == 0 { // Stored
                fileData = Data(bytes[dataStart..<dataEnd])
            } else if entry.method == 8 { // Deflated
                let compData = Data(bytes[dataStart..<dataEnd])
                fileData = try inflate(data: compData, expectedSize: Int(entry.uncompSize))
            } else {
                throw SignError.unsupportedCompression
            }
            try fileData.write(to: fileURL)
        }
    }

    private struct ZipEntry {
        let name: String
        let method: UInt16
        let compSize: UInt32
        let uncompSize: UInt32
        let localHeaderOffset: Int
    }

    private func readU16(_ bytes: [UInt8], _ off: Int) -> UInt16 {
        guard off >= 0, off + 1 < bytes.count else { return 0 }
        return UInt16(bytes[off]) | (UInt16(bytes[off+1]) << 8)
    }

    private func readU32(_ bytes: [UInt8], _ off: Int) -> UInt32 {
        guard off >= 0, off + 3 < bytes.count else { return 0 }
        return UInt32(bytes[off]) | (UInt32(bytes[off+1]) << 8) |
        (UInt32(bytes[off+2]) << 16) | (UInt32(bytes[off+3]) << 24)
    }

    private func parseCentralDirectory(_ bytes: [UInt8]) -> [ZipEntry]? {
        // Find EOCD (PK\x05\x06) scanning back from the end — a comment may follow it
        guard bytes.count >= 22 else { return nil }
        var eocd = -1
        var i = bytes.count - 22
        while i >= 0 {
            if bytes[i] == 0x50 && bytes[i+1] == 0x4B &&
               bytes[i+2] == 0x05 && bytes[i+3] == 0x06 {
                let commentLen = Int(readU16(bytes, i + 20))
                if i + 22 + commentLen == bytes.count { eocd = i; break }
            }
            i -= 1
        }
        guard eocd >= 0 else { return nil }
        let entryCount = Int(readU16(bytes, eocd + 10))
        let cdOffset = Int(readU32(bytes, eocd + 16))
        guard cdOffset < bytes.count, entryCount > 0 else { return nil }

        var entries: [ZipEntry] = []
        var off = cdOffset
        for _ in 0..<entryCount {
            guard off + 46 <= bytes.count,
                  bytes[off] == 0x50 && bytes[off+1] == 0x4B &&
                  bytes[off+2] == 0x01 && bytes[off+3] == 0x02 else { return nil }
            let method = readU16(bytes, off + 10)
            let compSize = readU32(bytes, off + 20)
            let uncompSize = readU32(bytes, off + 24)
            let nameLen = Int(readU16(bytes, off + 28))
            let extraLen = Int(readU16(bytes, off + 30))
            let commentLen = Int(readU16(bytes, off + 32))
            let localHeaderOffset = Int(readU32(bytes, off + 42))
            let nameStart = off + 46
            guard nameStart + nameLen <= bytes.count else { return nil }
            let nameData = Data(bytes[nameStart..<(nameStart + nameLen)])
            guard let name = String(data: nameData, encoding: .utf8), !name.isEmpty else { return nil }
            entries.append(ZipEntry(name: name, method: method, compSize: compSize,
                                    uncompSize: uncompSize, localHeaderOffset: localHeaderOffset))
            off = nameStart + nameLen + extraLen + commentLen
        }
        return entries
    }
    
    private func inflate(data: Data, expectedSize: Int) throws -> Data {
        // Pure Swift DEFLATE decoder (RFC 1951) — reliable, no framework quirks
        guard !data.isEmpty else { throw SignError.corruptZip }
        let decoder = DeflateDecoder(data: data)
        let result = try decoder.decode()
        guard result.count == expectedSize else { throw SignError.corruptZip }
        return result
    }
    // CRC32 (IEEE 802.3) for ZIP
    private func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFFFFFF
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xEDB88320 : crc >> 1
            }
        }
        return crc ^ 0xFFFFFFFF
    }

    private func zip(sourceDir: URL, to destURL: URL) throws {
        // Minimal ZIP writer (stored only for simplicity, or deflated)
        // For now, use stored (no compression) to keep it simple
        var zipData = Data()
        var centralDir: [(name: String, offset: UInt32, size: UInt32, crc: UInt32)] = []
        
        let enumerator = FileManager.default.enumerator(at: sourceDir, includingPropertiesForKeys: [.isRegularFileKey])
        while let file = enumerator?.nextObject() as? URL {
            let isDir = (try? file.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
            if isDir { continue }
            
            let relPath = file.path.replacingOccurrences(of: sourceDir.path + "/", with: "")
            let fileData = try Data(contentsOf: file)
            let crc = crc32(fileData)
            
            let offset = UInt32(zipData.count)
            
            // Local file header
            zipData.append(contentsOf: [0x50, 0x4B, 0x03, 0x04]) // Signature
            zipData.append(contentsOf: [0x14, 0x00]) // Version
            zipData.append(contentsOf: [0x00, 0x00]) // Flags
            zipData.append(contentsOf: [0x00, 0x00]) // Method: stored
            zipData.append(contentsOf: [0x00, 0x00, 0x00, 0x00]) // Time/date
            appendUInt32(&zipData, crc) // CRC32 (real)
            appendUInt32(&zipData, UInt32(fileData.count)) // Compressed size
            appendUInt32(&zipData, UInt32(fileData.count)) // Uncompressed size
            appendUInt16(&zipData, UInt16(relPath.utf8.count)) // Name length
            appendUInt16(&zipData, 0) // Extra length
            zipData.append(contentsOf: relPath.utf8)
            zipData.append(fileData)
            
            centralDir.append((relPath, offset, UInt32(fileData.count), crc))
        }
        
        let centralStart = UInt32(zipData.count)
        for entry in centralDir {
            zipData.append(contentsOf: [0x50, 0x4B, 0x01, 0x02]) // Signature
            zipData.append(contentsOf: [0x14, 0x00, 0x14, 0x00]) // Versions
            zipData.append(contentsOf: [0x00, 0x00]) // Flags
            zipData.append(contentsOf: [0x00, 0x00]) // Method: stored
            zipData.append(contentsOf: [0x00, 0x00]) // Mod time
            zipData.append(contentsOf: [0x00, 0x00]) // Mod date
            appendUInt32(&zipData, entry.crc) // CRC32 (real)
            appendUInt32(&zipData, entry.size)
            appendUInt32(&zipData, entry.size)
            appendUInt16(&zipData, UInt16(entry.name.utf8.count))
            appendUInt16(&zipData, 0) // Extra field length
            appendUInt16(&zipData, 0) // Comment length
            appendUInt16(&zipData, 0) // Disk number
            appendUInt16(&zipData, 0) // Internal attrs
            appendUInt32(&zipData, 0) // External attrs
            appendUInt32(&zipData, entry.offset)
            zipData.append(contentsOf: entry.name.utf8)
        }
        let centralSize = UInt32(zipData.count) - centralStart
        
        // End of central directory
        zipData.append(contentsOf: [0x50, 0x4B, 0x05, 0x06])
        zipData.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        appendUInt16(&zipData, UInt16(centralDir.count))
        appendUInt16(&zipData, UInt16(centralDir.count))
        appendUInt32(&zipData, centralSize)
        appendUInt32(&zipData, centralStart)
        appendUInt16(&zipData, 0)
        
        try zipData.write(to: destURL)
    }
    
    private func appendUInt16(_ data: inout Data, _ value: UInt16) {
        data.append(UInt8(value & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
    }
    
    func appendUInt32(_ data: inout Data, _ value: UInt32) {
        data.append(UInt8(value & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 24) & 0xFF))
    }
}

private class DeflateDecoder {
    private let data: [UInt8]
    private var bitPos = 0
    private var output = Data()
    
    init(data: Data) {
        self.data = [UInt8](data)
    }
    
    func decode() throws -> Data {
        var final = false
        while !final {
            final = try readBits(1) == 1
            let btype = try readBits(2)
            switch btype {
            case 0: try decodeStored()
            case 1: try decodeFixedHuffman()
            case 2: try decodeDynamicHuffman()
            default: throw SignError.corruptZip
            }
        }
        return output
    }
    
    private func readBits(_ n: Int) throws -> Int {
        var result = 0
        for i in 0..<n {
            let byteIdx = bitPos / 8
            let bitIdx = bitPos % 8
            guard byteIdx < data.count else { throw SignError.corruptZip }
            let bit = (data[byteIdx] >> bitIdx) & 1
            result |= (Int(bit) << i)
            bitPos += 1
        }
        return result
    }
    
    private func decodeStored() throws {
        // Skip to byte boundary
        while bitPos % 8 != 0 { bitPos += 1 }
        guard bitPos + 32 <= data.count * 8 else { throw SignError.corruptZip }
        let byteIdx = bitPos / 8
        let len = Int(data[byteIdx]) | (Int(data[byteIdx+1]) << 8)
        // let nlen = Int(data[byteIdx+2]) | (Int(data[byteIdx+3]) << 8)
        bitPos += 32
        let start = bitPos / 8
        guard start + len <= data.count else { throw SignError.corruptZip }
        output.append(contentsOf: data[start..<(start+len)])
        bitPos += len * 8
    }
    
    private func decodeFixedHuffman() throws {
        // Fixed Huffman tables (RFC 1951 section 3.2.6)
        // Literal/length: 0-143: 8 bits, 144-255: 9 bits, 256-279: 7 bits, 280-287: 8 bits
        // Distance: 0-31: 5 bits
        try decodeHuffman(litLenTable: fixedLitLenTable(), distTable: fixedDistTable())
    }
    
    private func decodeDynamicHuffman() throws {
        let hlit = try readBits(5) + 257
        let hdist = try readBits(5) + 1
        let hclen = try readBits(4) + 4
        
        // Code length order
        let order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
        var clLengths = [Int](repeating: 0, count: 19)
        for i in 0..<hclen {
            clLengths[order[i]] = try readBits(3)
        }
        let clTable = try buildHuffmanTable(lengths: clLengths)
        
        // Read literal/length and distance code lengths
        var lengths = [Int]()
        while lengths.count < hlit + hdist {
            let sym = try decodeHuffmanSymbol(table: clTable)
            if sym < 16 {
                lengths.append(sym)
            } else if sym == 16 {
                let repeat_ = try readBits(2) + 3
                let last = lengths.last ?? 0
                lengths.append(contentsOf: [Int](repeating: last, count: repeat_))
            } else if sym == 17 {
                let repeat_ = try readBits(3) + 3
                lengths.append(contentsOf: [Int](repeating: 0, count: repeat_))
            } else if sym == 18 {
                let repeat_ = try readBits(7) + 11
                lengths.append(contentsOf: [Int](repeating: 0, count: repeat_))
            }
        }
        
        let litLenTable = try buildHuffmanTable(lengths: Array(lengths[0..<hlit]))
        let distTable = try buildHuffmanTable(lengths: Array(lengths[hlit..<(hlit+hdist)]))
        try decodeHuffman(litLenTable: litLenTable, distTable: distTable)
    }
    
    private func decodeHuffman(litLenTable: HuffmanTable, distTable: HuffmanTable) throws {
        while true {
            let sym = try decodeHuffmanSymbol(table: litLenTable)
            if sym < 256 {
                output.append(UInt8(sym))
            } else if sym == 256 {
                break // End of block
            } else {
                // Length/distance pair
                let (length, distSym) = try decodeLength(sym: sym)
                let distance = try decodeDistance(sym: distSym, table: distTable)
                // Copy from output
                let start = output.count - distance
                guard start >= 0 else { throw SignError.corruptZip }
                for i in 0..<length {
                    output.append(output[start + i])
                }
            }
        }
    }
    
    private func decodeLength(sym: Int) throws -> (Int, Int) {
        // Returns (length, distance symbol to decode)
        let base: Int
        let extra: Int
        switch sym {
        case 257...264: base = sym - 254; extra = 0
        case 265...268: base = 11 + (sym - 265) * 2; extra = 1
        case 269...272: base = 19 + (sym - 269) * 4; extra = 2
        case 273...276: base = 35 + (sym - 273) * 8; extra = 3
        case 277...280: base = 67 + (sym - 277) * 16; extra = 4
        case 281...284: base = 131 + (sym - 281) * 32; extra = 5
        case 285: base = 258; extra = 0
        default: throw SignError.corruptZip
        }
        let length = base + (extra > 0 ? try readBits(extra) : 0)
        // Next symbol is distance - we need to decode it separately
        // For simplicity, return sym and let caller handle
        return (length, sym)
    }
    
    private func decodeDistance(sym: Int, table: HuffmanTable) throws -> Int {
        let distSym = try decodeHuffmanSymbol(table: table)
        let base: Int
        let extra: Int
        switch distSym {
        case 0...3: base = distSym + 1; extra = 0
        case 4...5: base = 5 + (distSym - 4) * 2; extra = 1
        case 6...7: base = 9 + (distSym - 6) * 4; extra = 2
        case 8...9: base = 17 + (distSym - 8) * 8; extra = 3
        case 10...11: base = 33 + (distSym - 10) * 16; extra = 4
        case 12...13: base = 65 + (distSym - 12) * 32; extra = 5
        case 14...15: base = 129 + (distSym - 14) * 64; extra = 6
        case 16...17: base = 257 + (distSym - 16) * 128; extra = 7
        case 18...19: base = 513 + (distSym - 18) * 256; extra = 8
        case 20...21: base = 1025 + (distSym - 20) * 512; extra = 9
        case 22...23: base = 2049 + (distSym - 22) * 1024; extra = 10
        case 24...25: base = 4097 + (distSym - 24) * 2048; extra = 11
        case 26...27: base = 8193 + (distSym - 26) * 4096; extra = 12
        case 28...29: base = 16385 + (distSym - 28) * 8192; extra = 13
        default: throw SignError.corruptZip
        }
        return base + (extra > 0 ? try readBits(extra) : 0)
    }
    
    // Huffman table structures
    private struct HuffmanTable {
        let codes: [Int: Int] // code -> symbol
        let maxLen: Int
    }
    
    private func fixedLitLenTable() -> HuffmanTable {
        var lengths = [Int](repeating: 0, count: 288)
        for i in 0..<144 { lengths[i] = 8 }
        for i in 144..<256 { lengths[i] = 9 }
        for i in 256..<280 { lengths[i] = 7 }
        for i in 280..<288 { lengths[i] = 8 }
        return (try? buildHuffmanTable(lengths: lengths)) ?? HuffmanTable(codes: [:], maxLen: 0)
    }
    
    private func fixedDistTable() -> HuffmanTable {
        let lengths = [Int](repeating: 5, count: 32)
        return (try? buildHuffmanTable(lengths: lengths)) ?? HuffmanTable(codes: [:], maxLen: 0)
    }
    
    private func buildHuffmanTable(lengths: [Int]) throws -> HuffmanTable {
        // Build canonical Huffman table
        var codes = [Int: Int]()
        var maxLen = 0
        for len in lengths { maxLen = max(maxLen, len) }
        
        // Count codes per length
        var blCount = [Int](repeating: 0, count: maxLen + 1)
        for len in lengths where len > 0 {
            blCount[len] += 1
        }
        
        // Compute first code for each length
        var nextCode = [Int](repeating: 0, count: maxLen + 1)
        var code = 0
        for bits in 1...maxLen {
            code = (code + blCount[bits-1]) << 1
            nextCode[bits] = code
        }
        
        // Assign codes
        for (n, len) in lengths.enumerated() where len > 0 {
            // Reverse bits (DEFLATE uses LSB-first)
            var rev = 0
            var c = nextCode[len]
            for _ in 0..<len {
                rev = (rev << 1) | (c & 1)
                c >>= 1
            }
            codes[(rev << 8) | len] = n
            nextCode[len] += 1
        }
        
        return HuffmanTable(codes: codes, maxLen: maxLen)
    }
    
    private func decodeHuffmanSymbol(table: HuffmanTable) throws -> Int {
        var code = 0
        for len in 1...table.maxLen {
            let bit = try readBits(1)
            code |= (bit << (len - 1))
            // Note: bits are read LSB-first, need to match table construction
            let key = (code << 8) | len
            if let sym = table.codes[key] {
                return sym
            }
        }
        throw SignError.corruptZip
    }
}


enum SignError: Error, LocalizedError {
    case certificateNotFound
    case invalidPassword
    case appBundleNotFound
    case plistError
    case unsupportedCompression
    case corruptZip
    case signingNotFullyImplemented
    case signingFailed(String)
    
    var errorDescription: String? {
        switch self {
        case .certificateNotFound: return "Certificate not found"
        case .invalidPassword: return "Invalid certificate password"
        case .appBundleNotFound: return "App bundle not found in IPA"
        case .plistError: return "Failed to update Info.plist"
        case .unsupportedCompression: return "Unsupported ZIP compression"
        case .corruptZip: return "Corrupt ZIP file"
        case .signingNotFullyImplemented: return "Binary signing requires full Mach-O implementation"
        case .signingFailed(let msg): return "Signing failed: \(msg)"
        }
    }
}
