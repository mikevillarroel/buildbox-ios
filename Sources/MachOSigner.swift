import Foundation
import CryptoKit

// MARK: - Mach-O Code Signing
// Implements real LC_CODE_SIGNATURE generation for iOS binaries

// Apple WWDR G3 Intermediate CA (required in CMS chain for iOS to verify)
// Downloaded from https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer
private let appleWWDRG3Base64 = "MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZC4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbWBpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LSVpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsGAQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhMC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3JsMB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYwEAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJHQr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qAHXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETKXXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTCNwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVzaUDSdlTs="

// Apple Root CA (codesign includes it in CMS chain, iOS expects it)
// Extracted from macOS SystemRootCertificates.keychain
private let appleRootCABase64 = "MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg++FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9wtj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IWq6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKMaLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAEggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBcNplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQPy3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4FgxhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oPIQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AXUKqK1drk/NAJBzewdXUh"

struct MachOHeader {
    let magic: UInt32
    let cputype: Int32
    let cpusubtype: Int32
    let filetype: UInt32
    let ncmds: UInt32
    let sizeofcmds: UInt32
    let flags: UInt32
    let reserved: UInt32
    let is64Bit: Bool
}

struct LoadCommand {
    let cmd: UInt32
    let cmdsize: UInt32
    let offset: Int
}

struct SegmentCommand {
    let segname: String
    let vmaddr: UInt64
    let vmsize: UInt64
    let fileoff: UInt64
    let filesize: UInt64
}

class MachOSigner {
    
    // MARK: - Parse Mach-O header
    static func parseHeader(data: Data) throws -> (header: MachOHeader, commands: [LoadCommand]) {
        guard data.count >= 32 else { throw SignError.corruptZip }
        let bytes = [UInt8](data)
        
        let magic = UInt32(bytes[0]) | (UInt32(bytes[1]) << 8) | (UInt32(bytes[2]) << 16) | (UInt32(bytes[3]) << 24)
        let is64Bit = (magic == 0xFEEDFACF || magic == 0xCFFAEDFE) // MH_MAGIC_64 (BE and LE)
        
        guard magic == 0xFEEDFACE || magic == 0xFEEDFACF || magic == 0xCEFAEDFE || magic == 0xCFFAEDFE else {
            throw SignError.corruptZip
        }
        
        func readU32(_ offset: Int) -> UInt32 {
            return UInt32(bytes[offset]) | (UInt32(bytes[offset+1]) << 8) |
                   (UInt32(bytes[offset+2]) << 16) | (UInt32(bytes[offset+3]) << 24)
        }
        func readI32(_ offset: Int) -> Int32 {
            return Int32(bitPattern: readU32(offset))
        }
        
        let header = MachOHeader(
            magic: magic,
            cputype: readI32(4),
            cpusubtype: readI32(8),
            filetype: readU32(12),
            ncmds: readU32(16),
            sizeofcmds: readU32(20),
            flags: readU32(24),
            reserved: is64Bit ? readU32(28) : 0,
            is64Bit: is64Bit
        )
        
        var commands: [LoadCommand] = []
        var offset = is64Bit ? 32 : 28
        for _ in 0..<header.ncmds {
            guard offset + 8 <= data.count else { break }
            let cmd = readU32(offset)
            let cmdsize = readU32(offset + 4)
            guard cmdsize >= 8 && offset + Int(cmdsize) <= data.count else { break }
            commands.append(LoadCommand(cmd: cmd, cmdsize: cmdsize, offset: offset))
            offset += Int(cmdsize)
        }
        
        return (header, commands)
    }
    
    // MARK: - Compute code directory hashes
    static func computePageHashes(data: Data, codeOffset: Int, codeSize: Int, pageSize: Int = 4096, useSHA1: Bool = false) -> [Data] {
        var hashes: [Data] = []
        var offset = codeOffset
        let end = codeOffset + codeSize
        
        while offset < end {
            let chunkSize = min(pageSize, end - offset)
            let chunk = data[offset..<(offset + chunkSize)]
            if useSHA1 {
                let hash = Insecure.SHA1.hash(data: chunk)
                hashes.append(Data(hash))
            } else {
                let hash = SHA256.hash(data: chunk)
                hashes.append(Data(hash))
            }
            offset += chunkSize
        }
        
        return hashes
    }
    
    // MARK: - Build CodeDirectory blob
    // Format per Apple docs: https://developer.apple.com/documentation/security/code_signing
    static func buildCodeDirectory(identifier: String, pageHashes: [Data], codeLimit: UInt64, teamID: String? = nil, useSHA1: Bool = false) -> Data {
        var dir = Data()
        
        // Header (all big-endian)
        func appendU32BE(_ value: UInt32) {
            dir.append(UInt8((value >> 24) & 0xFF))
            dir.append(UInt8((value >> 16) & 0xFF))
            dir.append(UInt8((value >> 8) & 0xFF))
            dir.append(UInt8(value & 0xFF))
        }
        func appendU64BE(_ value: UInt64) {
            appendU32BE(UInt32((value >> 32) & 0xFFFFFFFF))
            appendU32BE(UInt32(value & 0xFFFFFFFF))
        }
        
        let magic: UInt32 = 0xFADE0C02 // CSMAGIC_CODEDIRECTORY
        let length: UInt32 = 0 // placeholder, fill later
        let version: UInt32 = 0x20500 // CS_SUPPORTSEXECSEG etc. (Dadoum reference)
        let flags: UInt32 = 0
        let hashOffset: UInt32 = 0 // placeholder
        let identOffset: UInt32 = 0 // placeholder
        let nSpecialSlots: UInt32 = 7
        let nCodeSlots: UInt32 = UInt32(pageHashes.count)
        let codeLimit: UInt32 = UInt32(codeLimit)
        let hashSize: UInt8 = useSHA1 ? 20 : 32 // SHA-1=20, SHA-256=32
        let hashType: UInt8 = useSHA1 ? 1 : 2 // CS_HASHTYPE_SHA1=1, CS_HASHTYPE_SHA256=2
        let platform: UInt8 = 0
        let pageSize: UInt8 = 12 // 2^12 = 4096 (Dadoum reference)
        let spare2: UInt32 = 0
        let scatterOffset: UInt32 = 0
        let teamOffset: UInt32 = 0 // placeholder, filled later if teamID present
        
        appendU32BE(magic)
        let lengthPos = dir.count
        appendU32BE(length)
        appendU32BE(version)
        appendU32BE(flags)
        let hashOffsetPos = dir.count
        appendU32BE(hashOffset)
        let identOffsetPos = dir.count
        appendU32BE(identOffset)
        appendU32BE(nSpecialSlots)
        appendU32BE(nCodeSlots)
        appendU32BE(codeLimit)
        dir.append(hashSize)
        dir.append(hashType)
        dir.append(platform)
        dir.append(pageSize)
        appendU32BE(spare2)
        appendU32BE(scatterOffset)
        let teamOffsetPos = dir.count
        appendU32BE(teamOffset)
        
        // Hash offset points here
        let hashStart = dir.count
        for hash in pageHashes {
            dir.append(hash)
        }
        
        // Identifier offset points here
        let identStart = dir.count
        dir.append(contentsOf: identifier.utf8)
        dir.append(0) // null terminator
        
        // Team ID (if present)
        var teamStart: UInt32 = 0
        if let tid = teamID, !tid.isEmpty {
            teamStart = UInt32(dir.count)
            dir.append(contentsOf: tid.utf8)
            dir.append(0) // null terminator
        }
        
        // Fill in offsets
        let totalLength = UInt32(dir.count)
        func patchU32BE(at pos: Int, value: UInt32) {
            dir[pos] = UInt8((value >> 24) & 0xFF)
            dir[pos+1] = UInt8((value >> 16) & 0xFF)
            dir[pos+2] = UInt8((value >> 8) & 0xFF)
            dir[pos+3] = UInt8(value & 0xFF)
        }
        patchU32BE(at: lengthPos, value: totalLength)
        patchU32BE(at: hashOffsetPos, value: UInt32(hashStart))
        patchU32BE(at: identOffsetPos, value: UInt32(identStart))
        if teamStart != 0 {
            patchU32BE(at: teamOffsetPos, value: teamStart)
        }
        
        return dir
    }
    
    // MARK: - Build SuperBlob
    // SuperBlob slots: 0=CodeDirectory, 0x1000=Alternate CD, 2=Requirements, 5=Entitlements, 7=DER Entitlements, 0x10000=Signature (CMS)
    static func buildSuperBlob(codeDirectory: Data, alternateCD: Data? = nil, entitlements: Data? = nil, cmsSignature: Data? = nil) -> Data {
        var blob = Data()

        func appendU32BE(_ value: UInt32) {
            blob.append(UInt8((value >> 24) & 0xFF))
            blob.append(UInt8((value >> 16) & 0xFF))
            blob.append(UInt8((value >> 8) & 0xFF))
            blob.append(UInt8(value & 0xFF))
        }

        func blobWithHeader(magic: UInt32, payload: Data) -> Data {
            var b = Data()
            b.append(UInt8((magic >> 24) & 0xFF)); b.append(UInt8((magic >> 16) & 0xFF))
            b.append(UInt8((magic >> 8) & 0xFF)); b.append(UInt8(magic & 0xFF))
            let len = UInt32(payload.count + 8)
            b.append(UInt8((len >> 24) & 0xFF)); b.append(UInt8((len >> 16) & 0xFF))
            b.append(UInt8((len >> 8) & 0xFF)); b.append(UInt8(len & 0xFF))
            b.append(payload)
            return b
        }

        let magic: UInt32 = 0xFADE0CC0 // CSMAGIC_EMBEDDED_SIGNATURE

        // Collect slots in order: CodeDirectory (0), Alternate CD (0x1000), Requirements (2), Entitlements (5), DER Entitlements (7), Signature (0x10000)
        var slots: [(type: UInt32, blob: Data)] = []
        // CodeDirectory already has magic+length header from buildCodeDirectory - use directly (no double-wrap!)
        slots.append((0, codeDirectory)) // CSMAGIC_CODEDIRECTORY (SHA-1 primary)
        // Alternate CodeDirectory (SHA-256) at slot 0x1000
        if let altCD = alternateCD {
            slots.append((0x1000, altCD))
        }
        // Requirements slot (slot 2, not slot 1!)
        let emptyReqs = blobWithHeader(magic: 0xFADE0C01, payload: Data()) // CSMAGIC_REQUIREMENTS
        slots.append((2, emptyReqs))
        if let ent = entitlements {
            slots.append((5, blobWithHeader(magic: 0xFADE7171, payload: ent))) // CSMAGIC_ENTITLEMENT (Apple's real magic)
            // DER Entitlements (slot 7) - REQUIRED for executables
            // For now, use the same entitlements data (should be DER-encoded, but XML may work)
            slots.append((7, blobWithHeader(magic: 0xFADE7172, payload: ent))) // CSMAGIC_DER_ENTITLEMENT (Apple's real magic)
        }
        if let cms = cmsSignature {
            // CMS MUST be wrapped in 0xfade0b01 blob wrapper (CSMAGIC_BLOBWRAPPER)
            slots.append((0x10000, blobWithHeader(magic: 0xFADE0B01, payload: cms))) // CSSLOT_SIGNATURESLOT
        }

        let slotCount = UInt32(slots.count)
        appendU32BE(magic)
        let lengthPos = blob.count
        appendU32BE(0) // placeholder
        appendU32BE(slotCount)

        // Compute offsets (header 12 bytes + 8 per slot entry)
        var offset = UInt32(12 + slots.count * 8)
        var offsets: [UInt32] = []
        for s in slots {
            // Align each blob to 16 bytes (except CMS which follows entitlements directly is fine aligned)
            while offset % 16 != 0 { offset += 1 }
            offsets.append(offset)
            offset += UInt32(s.blob.count)
        }

        for (i, s) in slots.enumerated() {
            appendU32BE(s.type)
            appendU32BE(offsets[i])
        }

        for (i, s) in slots.enumerated() {
            while blob.count < Int(offsets[i]) { blob.append(0) }
            blob.append(s.blob)
        }

        // Fill total length
        let totalLen = UInt32(blob.count)
        blob[lengthPos] = UInt8((totalLen >> 24) & 0xFF)
        blob[lengthPos+1] = UInt8((totalLen >> 16) & 0xFF)
        blob[lengthPos+2] = UInt8((totalLen >> 8) & 0xFF)
        blob[lengthPos+3] = UInt8(totalLen & 0xFF)

        return blob
    }
    
    /// Create a SecTrust to build the certificate chain
    private static func createTrustChain(for certificate: SecCertificate) -> SecTrust? {
        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        let status = SecTrustCreateWithCertificates(certificate, policy, &trust)
        guard status == errSecSuccess else { return nil }
        return trust
    }

    /// Check if a certificate is self-signed (issuer == subject)
    private static func isSelfSigned(certDER: Data) -> Bool {
        // Parse to get issuer and subject, compare their DER
        guard let certElems = DER.parseSequence(certDER), certElems.count >= 1,
              let tbsElems = DER.parseSequence(certElems[0]) else { return false }
        var idx = 0
        if idx < tbsElems.count, [UInt8](tbsElems[idx])[0] == 0xA0 { idx += 1 }
        idx += 1 // serial
        idx += 1 // signature
        guard idx < tbsElems.count else { return false }
        let issuerDER = tbsElems[idx]
        idx += 1 // validity
        guard idx < tbsElems.count else { return false }
        let subjectDER = tbsElems[idx]
        return issuerDER == subjectDER
    }

    // MARK: - Create CMS signature
    // Builds a proper DER-encoded CMS SignedData per RFC 5652
    static func createCMSSignature(codeDirectory: Data, alternateCD: Data? = nil, identity: SecIdentity) throws -> Data {
        // Hash the CodeDirectories (cdhash = SHA-256 of each CD)
        let cdHash = Data(SHA256.hash(data: codeDirectory))
        var cdHashes: [Data] = [cdHash]
        if let altCD = alternateCD {
            let altHash = Data(SHA256.hash(data: altCD))
            cdHashes.append(altHash)
        }

        // Get the certificate DER
        var certRef: SecCertificate?
        let certStatus = SecIdentityCopyCertificate(identity, &certRef)
        guard certStatus == errSecSuccess, let certificate = certRef else {
            throw SignError.certificateNotFound
        }
        let certDER = SecCertificateCopyData(certificate) as Data

        // Build the full certificate chain (leaf + intermediates) via SecTrust
        // iOS needs the intermediate CA to verify the chain to Apple Root
        var chainDERs: [Data] = [certDER]
        if let trust = createTrustChain(for: certificate) {
            let count = SecTrustGetCertificateCount(trust)
            // Index 0 is the leaf (already have it), add intermediates (skip root)
            for i in 1..<count {
                if let chainCert = SecTrustGetCertificateAtIndex(trust, i) {
                    let chainDER = SecCertificateCopyData(chainCert) as Data
                    // Skip self-signed root (issuer == subject)
                    if !isSelfSigned(certDER: chainDER) {
                        chainDERs.append(chainDER)
                    }
                }
            }
        }
        // Always include Apple WWDR G3 (iOS requires it to verify the chain)
        // SecTrust often doesn't return it, so we embed it directly
        if let wwdrG3DER = Data(base64Encoded: appleWWDRG3Base64) {
            // Avoid duplicate if SecTrust already included it
            if !chainDERs.contains(wwdrG3DER) {
                chainDERs.append(wwdrG3DER)
            }
        }
        // Always include Apple Root CA (Apple's codesign includes it in CMS)
        if let rootCADER = Data(base64Encoded: appleRootCABase64) {
            if !chainDERs.contains(rootCADER) {
                chainDERs.append(rootCADER)
            }
        }

        // Extract issuer (full DER) and serial (content bytes) for SignerIdentifier
        guard let (issuerDER, serialContent) = DER.extractIssuerAndSerial(from: certDER) else {
            throw SignError.signingNotFullyImplemented
        }

        // Get private key
        var privateKey: SecKey?
        let keyStatus = SecIdentityCopyPrivateKey(identity, &privateKey)
        guard keyStatus == errSecSuccess, let key = privateKey else {
            throw SignError.certificateNotFound
        }

        // Build signedAttrs content (SET OF Attribute, DER sorted by OID)
        // Attribute 1: contentType = 1.2.840.113549.1.7.1 (data)
        let contentTypeAttr = DER.sequence(
            DER.oid("1.2.840.113549.1.9.3") + DER.set(DER.oid("1.2.840.113549.1.7.1"))
        )
        // Attribute 2: messageDigest = OCTET STRING(cdHash)
        let messageDigestAttr = DER.sequence(
            DER.oid("1.2.840.113549.1.9.4") + DER.set(DER.octetString(cdHash))
        )
        // Attribute 3: Apple 1.2.840.113635.100.9.1 = SEQUENCE of CodeDirectory hashes
        var cdHashSeq = Data()
        for h in cdHashes {
            cdHashSeq.append(DER.octetString(h))
        }
        let appleCDHashesAttr = DER.sequence(
            DER.oid("1.2.840.113635.100.9.1") + DER.set(DER.sequence(cdHashSeq))
        )
        // Attribute 4: Apple 1.2.840.113635.100.9.2 = plist with cdhashes
        var cdhashArrayXML = ""
        for h in cdHashes {
            cdhashArrayXML += "<data>\(h.base64EncodedString())</data>\n"
        }
        let cdhashPlist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
        <key>cdhashes</key>
        <array>
        \(cdhashArrayXML)</array>
        </dict>
        </plist>
        """.data(using: .utf8)!
        let appleCdhashesAttr = DER.sequence(
            DER.oid("1.2.840.113635.100.9.2") + DER.set(DER.octetString(cdhashPlist))
        )
        // DER SET OF ordering: sort by FULL DER encoding bytes (not just OID!)
        // Each Attribute is SEQUENCE { OID, SET { value } }, and the lengths
        // differ, so ordering by OID alone is WRONG. Must sort by complete bytes.
        let sortedAttrs = [contentTypeAttr, messageDigestAttr, appleCDHashesAttr, appleCdhashesAttr]
            .sorted { lhs, rhs in
                lhs.lexicographicallyPrecedes(rhs)
            }
        var attrsContent = Data()
        for attr in sortedAttrs {
            attrsContent.append(attr)
        }
        // For CMS: signature is computed over DER encoding of the SET OF (0x31),
        // NOT the [0] IMPLICIT tag. The [0] tag is only in the final encoding.
        let signedAttrsSetDER = DER.tlv(tag: 0x31, content: attrsContent)
        // signedAttrs in SignerInfo is [0] IMPLICIT SET OF Attribute (0xA0)
        let signedAttrsDER = DER.tlv(tag: 0xA0, content: attrsContent)

        // Sign the DER-encoded SET (not the tagged version) per RFC 5652
        var cfError: Unmanaged<CFError>?
        var rawSignature: Data?
        var sigAlgOID = ""
        var isRSA = false

        // Try ECDSA first, then RSA (Apple dev certs are RSA)
        rawSignature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                              signedAttrsSetDER as CFData, &cfError) as Data?
        if rawSignature != nil {
            sigAlgOID = "1.2.840.10045.4.3.2" // ecdsa-with-SHA256
            isRSA = false
        } else {
            cfError = nil
            rawSignature = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256,
                                                  signedAttrsSetDER as CFData, &cfError) as Data?
            if rawSignature != nil {
                sigAlgOID = "1.2.840.113549.1.1.11" // sha256WithRSAEncryption
                isRSA = true
            }
        }

        guard var sigBytes = rawSignature else {
            throw SignError.signingNotFullyImplemented
        }

        // For ECDSA, convert raw R||S to DER SEQUENCE { INTEGER r, INTEGER s }
        if !isRSA {
            let half = sigBytes.count / 2
            let r = sigBytes[0..<half]
            let s = sigBytes[half..<sigBytes.count]
            sigBytes = DER.sequence(DER.integerData(r) + DER.integerData(s))
        }

        return try buildCMSSignedData(
            signature: sigBytes,
            sigAlgOID: sigAlgOID,
            isRSA: isRSA,
            signedAttrsDER: signedAttrsDER,
            chainDERs: chainDERs,
            issuerDER: issuerDER,
            serialContent: serialContent
        )
    }

    private static func buildCMSSignedData(signature: Data, sigAlgOID: String, isRSA: Bool,
                                           signedAttrsDER: Data, chainDERs: [Data],
                                           issuerDER: Data, serialContent: Data) throws -> Data {
        let sha256OID = "2.16.840.1.101.3.4.2.1"
        let signedDataOID = "1.2.840.113549.1.7.2"
        let dataOID = "1.2.840.113549.1.7.1"

        // DigestAlgorithmIdentifier: SEQUENCE { OID sha256, NULL }
        let digestAlg = DER.sequence(DER.oid(sha256OID) + DER.null())

        // EncapContentInfo: SEQUENCE { OID data } (no eContent)
        let encapContentInfo = DER.sequence(DER.oid(dataOID))

        // Certificates [0] IMPLICIT SET OF Certificate (full chain: leaf + intermediates)
        var certsContent = Data()
        for c in chainDERs {
            certsContent.append(c)
        }
        // [0] IMPLICIT: tag 0xA0 directly wraps the certs (no inner SET per RFC 5652)
        let certs = DER.tlv(tag: 0xA0, content: certsContent)

        // SignerInfo
        // sid = issuerAndSerialNumber: SEQUENCE { issuer, serial INTEGER }
        let sid = DER.sequence(issuerDER + DER.integerData(serialContent))
        // signatureAlgorithm
        var sigAlgParams = Data()
        if isRSA {
            sigAlgParams = DER.null()
        }
        // For ECDSA, params are absent
        let sigAlg = DER.sequence(DER.oid(sigAlgOID) + sigAlgParams)

        let signerInfo = DER.sequence(
            DER.integer(1) +           // version
            sid +                       // sid
            digestAlg +                 // digestAlgorithm
            signedAttrsDER +            // signedAttrs [0]
            sigAlg +                    // signatureAlgorithm
            DER.octetString(signature)  // signature
        )

        // SignedData
        let signedData = DER.sequence(
            DER.integer(3) +            // version
            DER.set(digestAlg) +        // digestAlgorithms
            encapContentInfo +          // encapContentInfo
            certs +                     // certificates [0]
            DER.set(signerInfo)         // signerInfos
        )

        // ContentInfo: SEQUENCE { OID signedData, [0] EXPLICIT SignedData }
        let contentInfo = DER.sequence(
            DER.oid(signedDataOID) +
            DER.tlv(tag: 0xA0, content: signedData) // [0] EXPLICIT
        )

        return contentInfo
    }
    
    // MARK: - Insert placeholder LC_CODE_SIGNATURE (before hashing)
    /// Inserts an LC_CODE_SIGNATURE load command pointing at end-of-file with size 0.
    /// Call this BEFORE computing page hashes, so hashes cover the final header layout.
    /// Adds an LC_LOAD_DYLIB command for `installPath` into a Mach-O executable
    /// (thin arm64 or the arm64 slice of a fat binary). The command is written
    /// into the zero padding after the existing load commands, so no file
    /// offsets move. The binary must be re-signed afterwards (BuildBox signs
    /// right after injecting). Throws if there is no room — never corrupts.
    static func addLoadDylib(executableURL: URL, installPath: String) throws {
        var bytes = [UInt8](try Data(contentsOf: executableURL))
        func u32le(_ o: Int) -> UInt32 { UInt32(bytes[o]) | UInt32(bytes[o+1]) << 8 | UInt32(bytes[o+2]) << 16 | UInt32(bytes[o+3]) << 24 }
        func u32be(_ o: Int) -> UInt32 { UInt32(bytes[o]) << 24 | UInt32(bytes[o+1]) << 16 | UInt32(bytes[o+2]) << 8 | UInt32(bytes[o+3]) }
        func put32le(_ o: Int, _ v: UInt32) { bytes[o] = UInt8(v & 0xff); bytes[o+1] = UInt8((v >> 8) & 0xff); bytes[o+2] = UInt8((v >> 16) & 0xff); bytes[o+3] = UInt8((v >> 24) & 0xff) }

        var base = 0
        if bytes.count >= 8 && u32be(0) == 0xCAFEBABE {
            // Fat binary: locate the arm64 slice (CPU_TYPE_ARM64 = 0x0100000C).
            let nfat = Int(u32be(4))
            var found: Int? = nil
            for i in 0..<nfat {
                let e = 8 + i * 20
                if e + 12 <= bytes.count && u32be(e) == 0x0100000C { found = Int(u32be(e + 8)); break }
            }
            guard let off = found else { throw NSError(domain: "MachOInject", code: 1, userInfo: [NSLocalizedDescriptionKey: "Injection: no arm64 slice in this binary"]) }
            base = off
        }
        guard base + 32 <= bytes.count, u32le(base) == 0xFEEDFACF else {
            throw NSError(domain: "MachOInject", code: 2, userInfo: [NSLocalizedDescriptionKey: "Injection: not a 64-bit Mach-O binary"])
        }

        let ncmds = Int(u32le(base + 16))
        let sizeofcmds = Int(u32le(base + 20))
        let cmdsStart = base + 32
        let cmdsEnd = cmdsStart + sizeofcmds

        // Walk the load commands: duplicate check + find the first real file
        // offset after the commands (the free padding ends there).
        var off = cmdsStart
        var minOff = Int.max
        var already = false
        for _ in 0..<ncmds {
            if off + 8 > bytes.count { break }
            let cmd = u32le(off)
            let size = Int(u32le(off + 4))
            if size < 8 { break }
            if cmd == 0x19 { // LC_SEGMENT_64
                let fileoff = Int(u32le(off + 40)) | Int(u32le(off + 44)) << 32
                let filesize = Int(u32le(off + 48)) | Int(u32le(off + 52)) << 32
                if fileoff > 0 && filesize > 0 { minOff = min(minOff, fileoff) }
                let nsects = Int(u32le(off + 64))
                for si in 0..<nsects {
                    let so = off + 72 + si * 80
                    if so + 52 <= bytes.count {
                        let soff = Int(u32le(so + 48))
                        if soff > 0 { minOff = min(minOff, soff) }
                    }
                }
            }
            if cmd == 0x0C || cmd == 0x80000018 || cmd == 0x8000001C || cmd == 0x18 {
                let nameOff = Int(u32le(off + 8))
                if nameOff >= 24 && nameOff < size {
                    let start = off + nameOff
                    var end = start
                    while end < off + size && bytes[end] != 0 { end += 1 }
                    if String(bytes: bytes[start..<end], encoding: .utf8) == installPath { already = true }
                }
            }
            off += size
        }
        if already { return }

        let pathBytes = [UInt8](installPath.utf8) + [0]
        let cmdsize = (24 + pathBytes.count + 7) & ~7
        guard minOff != Int.max, cmdsEnd + cmdsize <= minOff else {
            throw NSError(domain: "MachOInject", code: 3, userInfo: [NSLocalizedDescriptionKey: "Injection: no room for a new load command in \(executableURL.lastPathComponent)"])
        }

        var cmd = [UInt8](repeating: 0, count: cmdsize)
        func cput(_ o: Int, _ v: UInt32) { cmd[o] = UInt8(v & 0xff); cmd[o+1] = UInt8((v >> 8) & 0xff); cmd[o+2] = UInt8((v >> 16) & 0xff); cmd[o+3] = UInt8((v >> 24) & 0xff) }
        cput(0, 0x0C)            // LC_LOAD_DYLIB
        cput(4, UInt32(cmdsize))
        cput(8, 24)              // name offset
        cput(12, 2)              // timestamp
        cput(16, 0)              // current version
        cput(20, 0)              // compatibility version
        for i in 0..<pathBytes.count { cmd[24 + i] = pathBytes[i] }
        bytes.replaceSubrange(cmdsEnd..<(cmdsEnd + cmdsize), with: cmd)
        put32le(base + 16, UInt32(ncmds + 1))
        put32le(base + 20, UInt32(sizeofcmds + cmdsize))
        try Data(bytes).write(to: executableURL)
    }

    static func insertPlaceholderSignature(machoData: inout Data) throws {
        let (header, commands) = try parseHeader(data: machoData)
        let LC_CODE_SIGNATURE: UInt32 = 0x1D

        // Remove existing signature command if present (re-signing)
        for cmd in commands {
            if cmd.cmd == LC_CODE_SIGNATURE {
                machoData.removeSubrange(cmd.offset..<(cmd.offset + 16))
                func patchU32LE(at offset: Int, value: UInt32) {
                    machoData[offset] = UInt8(value & 0xFF)
                    machoData[offset+1] = UInt8((value >> 8) & 0xFF)
                    machoData[offset+2] = UInt8((value >> 16) & 0xFF)
                    machoData[offset+3] = UInt8((value >> 24) & 0xFF)
                }
                let bytes = [UInt8](machoData)
                let oldNcmds = UInt32(bytes[16]) | (UInt32(bytes[17]) << 8) |
                               (UInt32(bytes[18]) << 16) | (UInt32(bytes[19]) << 24)
                let oldSize = UInt32(bytes[20]) | (UInt32(bytes[21]) << 8) |
                              (UInt32(bytes[22]) << 16) | (UInt32(bytes[23]) << 24)
                patchU32LE(at: 16, value: oldNcmds - 1)
                patchU32LE(at: 20, value: oldSize - 16)
                break
            }
        }

        let (newHeader, newCommands) = try parseHeader(data: machoData)

        // Placeholder points at end of file, size 0 (filled in by finalizeSignature)
        let placeholderOffset = UInt32(machoData.count)

        var newCmd = Data()
        func appendU32LE(_ value: UInt32) {
            newCmd.append(UInt8(value & 0xFF))
            newCmd.append(UInt8((value >> 8) & 0xFF))
            newCmd.append(UInt8((value >> 16) & 0xFF))
            newCmd.append(UInt8((value >> 24) & 0xFF))
        }
        appendU32LE(LC_CODE_SIGNATURE)
        appendU32LE(16)
        appendU32LE(placeholderOffset)
        appendU32LE(0) // size filled later

        var lastCmdEnd = newHeader.is64Bit ? 32 : 28
        for cmd in newCommands {
            lastCmdEnd = cmd.offset + Int(cmd.cmdsize)
        }
        machoData.insert(contentsOf: newCmd, at: lastCmdEnd)

        // CRITICAL: Update segment file offsets (+16) since we inserted 16 bytes
        // LC_SEGMENT_64 (0x19): fileoff is at offset+40 (8 bytes, little-endian)
        // ONLY update segments with fileoff > 0 (__TEXT at 0 includes the header, don't touch it)
        let LC_SEGMENT_64: UInt32 = 0x19
        let (updHeader, updCommands) = try parseHeader(data: machoData)
        for cmd in updCommands {
            if cmd.cmd == LC_SEGMENT_64 {
                // fileoff is 8 bytes at cmd.offset+40
                let off = cmd.offset + 40
                if off + 8 <= machoData.count {
                    let bytes = [UInt8](machoData[off..<(off+8)])
                    var fileoff: UInt64 = 0
                    for i in 0..<8 {
                        fileoff |= UInt64(bytes[i]) << (i * 8)
                    }
                    // Only update if fileoff > 0 (segments after the header)
                    // __TEXT (fileoff=0) includes the Mach-O header itself, don't shift it
                    if fileoff > 0 {
                        fileoff += 16
                        // Write back
                        for i in 0..<8 {
                            machoData[off+i] = UInt8((fileoff >> (i * 8)) & 0xFF)
                        }
                    }
                }
            }
        }

        func patchU32LE(at offset: Int, value: UInt32) {
            machoData[offset] = UInt8(value & 0xFF)
            machoData[offset+1] = UInt8((value >> 8) & 0xFF)
            machoData[offset+2] = UInt8((value >> 16) & 0xFF)
            machoData[offset+3] = UInt8((value >> 24) & 0xFF)
        }
        let bytes = [UInt8](machoData)
        let oldNcmds = UInt32(bytes[16]) | (UInt32(bytes[17]) << 8) |
                       (UInt32(bytes[18]) << 16) | (UInt32(bytes[19]) << 24)
        let oldSize = UInt32(bytes[20]) | (UInt32(bytes[21]) << 8) |
                      (UInt32(bytes[22]) << 16) | (UInt32(bytes[23]) << 24)
        patchU32LE(at: 16, value: oldNcmds + 1)
        patchU32LE(at: 20, value: oldSize + 16)
    }

    // MARK: - Finalize signature (after hashing)
    /// Appends the signature blob at the placeholder offset and updates LC_CODE_SIGNATURE size.
    static func finalizeSignature(machoData: inout Data, signature: Data) throws {
        let (_, commands) = try parseHeader(data: machoData)
        let LC_CODE_SIGNATURE: UInt32 = 0x1D

        guard let sigCmd = commands.first(where: { $0.cmd == LC_CODE_SIGNATURE }) else {
            throw SignError.corruptZip
        }

        // Bounds check: ensure the LC_CODE_SIGNATURE command is within the data
        guard sigCmd.offset + 16 <= machoData.count else {
            throw SignError.corruptZip
        }

        // Read the placeholder offset (little-endian) - with bounds check
        let bytes = [UInt8](machoData)
        guard sigCmd.offset + 12 <= bytes.count else {
            throw SignError.corruptZip
        }
        let dataOff = Int(UInt32(bytes[sigCmd.offset+8]) | (UInt32(bytes[sigCmd.offset+9]) << 8) |
                          (UInt32(bytes[sigCmd.offset+10]) << 16) | (UInt32(bytes[sigCmd.offset+11]) << 24))

        // The placeholder was inserted before hashing, shifting data by 16.
        // dataOff was the file size at insert time; actual append point is end of file.
        // Verify it matches (it should, since we haven't appended anything since)
        let appendAt = machoData.count
        machoData.append(signature)

        func patchU32LE(at offset: Int, value: UInt32) throws {
            guard offset >= 0, offset + 3 < machoData.count else {
                throw SignError.corruptZip
            }
            machoData[offset] = UInt8(value & 0xFF)
            machoData[offset+1] = UInt8((value >> 8) & 0xFF)
            machoData[offset+2] = UInt8((value >> 16) & 0xFF)
            machoData[offset+3] = UInt8((value >> 24) & 0xFF)
        }
        try patchU32LE(at: sigCmd.offset + 8, value: UInt32(appendAt))
        try patchU32LE(at: sigCmd.offset + 12, value: UInt32(signature.count))
        _ = dataOff // placeholder offset, now superseded by appendAt
    }

    // MARK: - Insert LC_CODE_SIGNATURE (legacy combined version, kept for compatibility)
    static func insertCodeSignature(machoData: inout Data, signature: Data) throws {
        let (header, commands) = try parseHeader(data: machoData)
        let LC_CODE_SIGNATURE: UInt32 = 0x1D
        
        // Remove existing signature if present (re-signing case)
        for cmd in commands {
            if cmd.cmd == LC_CODE_SIGNATURE {
                // Remove the old LC_CODE_SIGNATURE command (16 bytes)
                let cmdOffset = cmd.offset
                machoData.removeSubrange(cmdOffset..<(cmdOffset + 16))
                
                // Update header: ncmds -= 1, sizeofcmds -= 16
                func patchU32LE(at offset: Int, value: UInt32) {
                    machoData[offset] = UInt8(value & 0xFF)
                    machoData[offset+1] = UInt8((value >> 8) & 0xFF)
                    machoData[offset+2] = UInt8((value >> 16) & 0xFF)
                    machoData[offset+3] = UInt8((value >> 24) & 0xFF)
                }
                let bytes = [UInt8](machoData)
                let oldNcmds = UInt32(bytes[16]) | (UInt32(bytes[17]) << 8) |
                               (UInt32(bytes[18]) << 16) | (UInt32(bytes[19]) << 24)
                let oldSize = UInt32(bytes[20]) | (UInt32(bytes[21]) << 8) |
                              (UInt32(bytes[22]) << 16) | (UInt32(bytes[23]) << 24)
                patchU32LE(at: 16, value: oldNcmds - 1)
                patchU32LE(at: 20, value: oldSize - 16)
                
                // Re-parse after removal
                break
            }
        }
        
        // Re-parse to get updated commands
        let (newHeader, newCommands) = try parseHeader(data: machoData)
        
        let sigOffset = machoData.count
        machoData.append(signature)
        
        var newCmd = Data()
        func appendU32LE(_ value: UInt32) {
            newCmd.append(UInt8(value & 0xFF))
            newCmd.append(UInt8((value >> 8) & 0xFF))
            newCmd.append(UInt8((value >> 16) & 0xFF))
            newCmd.append(UInt8((value >> 24) & 0xFF))
        }
        appendU32LE(LC_CODE_SIGNATURE)
        appendU32LE(16)
        appendU32LE(UInt32(sigOffset))
        appendU32LE(UInt32(signature.count))
        
        var lastCmdEnd = newHeader.is64Bit ? 32 : 28
        for cmd in newCommands {
            lastCmdEnd = cmd.offset + Int(cmd.cmdsize)
        }
        
        machoData.insert(contentsOf: newCmd, at: lastCmdEnd)
        
        func patchU32LE(at offset: Int, value: UInt32) {
            machoData[offset] = UInt8(value & 0xFF)
            machoData[offset+1] = UInt8((value >> 8) & 0xFF)
            machoData[offset+2] = UInt8((value >> 16) & 0xFF)
            machoData[offset+3] = UInt8((value >> 24) & 0xFF)
        }
        let bytes = [UInt8](machoData)
        let oldNcmds = UInt32(bytes[16]) | (UInt32(bytes[17]) << 8) |
                       (UInt32(bytes[18]) << 16) | (UInt32(bytes[19]) << 24)
        let oldSize = UInt32(bytes[20]) | (UInt32(bytes[21]) << 8) |
                      (UInt32(bytes[22]) << 16) | (UInt32(bytes[23]) << 24)
        patchU32LE(at: 16, value: oldNcmds + 1)
        patchU32LE(at: 20, value: oldSize + 16)
        patchU32LE(at: lastCmdEnd + 8, value: UInt32(sigOffset + 16))
    }
}

// MARK: - Entitlements extraction from provisioning profile

extension MachOSigner {
    /// Extract the Entitlements plist XML from a .mobileprovision file.
    /// The file is a CMS-signed blob containing an XML plist; we locate the
    /// plist payload, parse it, and re-serialize just the Entitlements dict.
    static func extractEntitlements(from provisionURL: URL) -> Data? {
        guard let data = try? Data(contentsOf: provisionURL) else { return nil }
        // Find plist boundaries inside the CMS wrapper
        guard let plistStart = data.range(of: Data("<?xml".utf8)),
              let plistEnd = data.range(of: Data("</plist>".utf8), options: .backwards) else {
            return nil
        }
        let plistData = data[plistStart.lowerBound..<plistEnd.upperBound]
        guard let plist = try? PropertyListSerialization.propertyList(from: Data(plistData), format: nil) as? [String: Any],
              let entitlements = plist["Entitlements"] as? [String: Any] else {
            return nil
        }
        // Serialize the entitlements dict as XML plist (this is what goes in slot 5)
        return try? PropertyListSerialization.data(fromPropertyList: entitlements, format: .xml, options: 0)
    }
}

// MARK: - DER Encoding Helpers (for CMS SignedData)

struct DER {
    static func encodeLength(_ len: Int) -> Data {
        var out = Data()
        if len < 0x80 {
            out.append(UInt8(len))
        } else {
            var tmp = len
            var bytes: [UInt8] = []
            while tmp > 0 {
                bytes.insert(UInt8(tmp & 0xFF), at: 0)
                tmp >>= 8
            }
            out.append(UInt8(0x80 | bytes.count))
            out.append(contentsOf: bytes)
        }
        return out
    }

    static func tlv(tag: UInt8, content: Data) -> Data {
        var out = Data()
        out.append(tag)
        out.append(encodeLength(content.count))
        out.append(content)
        return out
    }

    static func sequence(_ content: Data) -> Data {
        return tlv(tag: 0x30, content: content)
    }

    static func set(_ content: Data) -> Data {
        return tlv(tag: 0x31, content: content)
    }

    static func integer(_ value: Int) -> Data {
        var bytes: [UInt8] = []
        var v = value
        if v == 0 {
            bytes = [0]
        } else {
            while v > 0 {
                bytes.insert(UInt8(v & 0xFF), at: 0)
                v >>= 8
            }
            if bytes[0] & 0x80 != 0 {
                bytes.insert(0, at: 0)
            }
        }
        return tlv(tag: 0x02, content: Data(bytes))
    }

    static func integerData(_ data: Data) -> Data {
        var bytes = [UInt8](data)
        // Strip leading zeros, but keep one if high bit set
        while bytes.count > 1 && bytes[0] == 0 && (bytes[1] & 0x80) == 0 {
            bytes.removeFirst()
        }
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        return tlv(tag: 0x02, content: Data(bytes))
    }

    static func octetString(_ data: Data) -> Data {
        return tlv(tag: 0x04, content: data)
    }

    static func null() -> Data {
        return Data([0x05, 0x00])
    }

    static func oid(_ oidString: String) -> Data {
        let parts = oidString.split(separator: ".").compactMap { Int($0) }
        guard parts.count >= 2 else { return Data() }
        var out = Data()
        out.append(UInt8(40 * parts[0] + parts[1]))
        for i in 2..<parts.count {
            var v = parts[i]
            var stack: [UInt8] = []
            stack.append(UInt8(v & 0x7F))
            v >>= 7
            while v > 0 {
                stack.append(UInt8((v & 0x7F) | 0x80))
                v >>= 7
            }
            // Reverse (except last byte which has no continuation bit)
            for j in (0..<stack.count).reversed() {
                if j == 0 {
                    out.append(stack[j] & 0x7F)
                } else {
                    out.append(stack[j])
                }
            }
        }
        return tlv(tag: 0x06, content: out)
    }

    static func context(_ n: UInt8, content: Data, constructed: Bool = true) -> Data {
        let tag: UInt8 = (constructed ? 0xA0 : 0x80) | n
        return tlv(tag: tag, content: content)
    }

    // MARK: - Minimal DER Parser (for extracting issuer/serial from certs)

    struct TLV {
        let tag: UInt8
        let content: Data
        let totalLength: Int // tag + length + content
    }

    static func parse(_ data: Data, at offset: Int = 0) -> TLV? {
        let bytes = [UInt8](data)
        guard offset + 2 <= bytes.count else { return nil }
        let tag = bytes[offset]
        var pos = offset + 1
        let firstLen = bytes[pos]
        pos += 1
        var length = 0
        if firstLen & 0x80 == 0 {
            length = Int(firstLen)
        } else {
            let numBytes = Int(firstLen & 0x7F)
            guard numBytes > 0 && numBytes <= 4 && pos + numBytes <= bytes.count else { return nil }
            for i in 0..<numBytes {
                length = (length << 8) | Int(bytes[pos + i])
            }
            pos += numBytes
        }
        guard pos + length <= bytes.count else { return nil }
        // Use bytes array to avoid Data slice index issues
        let content = Data(bytes[pos..<(pos + length)])
        return TLV(tag: tag, content: content, totalLength: (pos + length) - offset)
    }

    static func parseSequence(_ data: Data) -> [Data]? {
        guard let outer = parse(data), outer.tag == 0x30 else { return nil }
        var elements: [Data] = []
        // Use a 0-based Data to avoid slice index issues
        let contentData = Data(outer.content)
        var pos = 0
        while pos < contentData.count {
            guard let tlv = parse(contentData, at: pos) else { return nil }
            // Reconstruct the full TLV (tag + length + content)
            let fullEnd = pos + tlv.totalLength
            // Bounds check to prevent crash on malformed DER
            guard fullEnd <= contentData.count, fullEnd > pos else { return nil }
            elements.append(contentData[pos..<fullEnd])
            pos = fullEnd
        }
        return elements
    }

    /// Extract (issuerDER, serialDER) from a DER-encoded X.509 certificate
    static func extractIssuerAndSerial(from certDER: Data) -> (issuer: Data, serial: Data)? {
        // Certificate ::= SEQUENCE { tbs, sigAlg, sig }
        guard let certElems = parseSequence(certDER), certElems.count >= 1 else { return nil }
        // TBSCertificate ::= SEQUENCE { [version], serial, sigAlg, issuer, ... }
        guard let tbsElems = parseSequence(certElems[0]) else { return nil }
        var idx = 0
        // Skip version [0] if present (tag 0xA0)
        if idx < tbsElems.count, !tbsElems[idx].isEmpty {
            let firstByte = [UInt8](tbsElems[idx])[0]
            if firstByte == 0xA0 { idx += 1 }
        }
        // Serial is next (INTEGER)
        guard idx < tbsElems.count else { return nil }
        guard let serialTLV = parse(tbsElems[idx]), serialTLV.tag == 0x02 else { return nil }
        let serialContent = serialTLV.content
        idx += 1
        // Skip signature algorithm
        idx += 1
        // Issuer is next (Name = SEQUENCE)
        guard idx < tbsElems.count else { return nil }
        // tbsElems[idx] is the full TLV (tag+length+content) for issuer
        let issuerFull = tbsElems[idx]
        guard let issuerTLV = parse(issuerFull), issuerTLV.tag == 0x30 else { return nil }
        return (issuer: issuerFull, serial: serialContent)
    }


    /// Extract the Organizational Unit (OU = Team ID) from a certificate's subject.
    /// The subject is in TBSCertificate after issuer, validity, subject.
    static func extractTeamID(from certDER: Data) -> String? {
        guard let certElems = parseSequence(certDER), certElems.count >= 1,
              let tbsElems = parseSequence(certElems[0]) else { return nil }
        var idx = 0
        if idx < tbsElems.count, !tbsElems[idx].isEmpty, [UInt8](tbsElems[idx])[0] == 0xA0 { idx += 1 } // version
        idx += 1 // serial
        idx += 1 // signature
        idx += 1 // issuer
        idx += 1 // validity
        guard idx < tbsElems.count else { return nil }
        // subject is a Name (SEQUENCE of RDNs)
        guard let subjectTLV = parse(tbsElems[idx]), subjectTLV.tag == 0x30 else { return nil }
        // Parse RDNs: SET OF { SEQUENCE { OID, value } }
        var pos = 0
        let subjectContent = subjectTLV.content
        let ouOID = Data([0x06, 0x03, 0x55, 0x04, 0x0B]) // 2.5.4.11
        while pos < subjectContent.count {
            guard let rdnSet = parse(subjectContent, at: pos), rdnSet.tag == 0x31 else { break }
            // Inside SET is a SEQUENCE { OID, value }
            guard let attrSeq = parse(rdnSet.content), attrSeq.tag == 0x30,
                  let attrElems = parseSequence(DER.tlv(tag: 0x30, content: attrSeq.content)) else {
                pos += rdnSet.totalLength
                continue
            }
            // Simpler: parse the content directly
            var apos = 0
            let ac = attrSeq.content
            guard let oidTLV = parse(ac, at: apos) else { pos += rdnSet.totalLength; continue }
            let oidFull = ac[apos..<(apos + oidTLV.totalLength)]
            apos += oidTLV.totalLength
            if Data(oidFull) == ouOID {
                // Next is the value (UTF8String 0x0C, PrintableString 0x13, etc.)
                guard let valTLV = parse(ac, at: apos) else { pos += rdnSet.totalLength; continue }
                return String(data: valTLV.content, encoding: .utf8)
            }
            pos += rdnSet.totalLength
        }
        return nil
    }
}
