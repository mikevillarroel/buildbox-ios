import Foundation

// MARK: - ZSign Wrapper
// Swift wrapper around the zsign C++ library (via bridging header)
// Based on KSign's ZsignHandler.swift

enum ZSign {
    /// Signs an app bundle using zsign
    /// - Parameters:
    ///   - appPath: Path to the .app bundle directory
    ///   - provisionPath: Path to .mobileprovision file (can be empty)
    ///   - p12Path: Path to .p12 certificate file
    ///   - p12Password: Password for the .p12
    ///   - bundleID: Custom bundle ID (optional)
    ///   - displayName: Custom display name (optional)
    ///   - version: Custom version (optional)
    /// - Returns: True if signing succeeded
    static func sign(
        appPath: String,
        provisionPath: String = "",
        p12Path: String,
        p12Password: String,
        bundleID: String = "",
        displayName: String = "",
        version: String = ""
    ) -> Bool {
        let semaphore = DispatchSemaphore(value: 0)
        var result = false
        
        // Call the C zsign function via bridging header
        // Note: C NSString* params bridge to Swift String — pass Strings directly
        // zsign(app, prov, key, pass, entitlement, bundleid, displayname, bundleversion, adhoc, dontGenerate, completion)
        zsign(
            appPath,
            provisionPath,
            p12Path,
            p12Password,
            "",  // entitlement path (empty = auto)
            bundleID,
            displayName,
            version,
            false,  // adhoc = false (use real cert)
            false,  // dontGenerateEmbeddedMobileProvision = false
            { success in
                result = success
                semaphore.signal()
            }
        )
        
        // Wait for completion (zsign is async)
        _ = semaphore.wait(timeout: .now() + 120)
        return result
    }
    
    /// Checks if a binary is signed
    static func isSigned(_ path: String) -> Bool {
        return CheckIfSigned(path)
    }
}
