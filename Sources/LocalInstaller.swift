import Foundation
import Network
import Security
import UIKit

// MARK: - Local HTTPS installer (replaces the old uguu/Gist upload flow)
// Serves manifest.plist + the signed IPA from THIS device over HTTPS on
// 127.0.0.1, then opens the itms-services URL. Nothing leaves the phone.
//
// One-time setup: the bundled self-signed installer certificate must be
// installed as a profile and trusted (Settings > General > About >
// Certificate Trust Settings). downloadCertificate() serves it for that.

class LocalInstaller {

    // The active server is retained statically so it outlives the button tap;
    // installd fetches the manifest and IPA after the app is backgrounded.
    private static var activeInstall: LocalInstaller?

    private var listener: NWListener?
    var logHandler: ((String) -> Void)?
    private var ipaFileURL: URL?
    private var manifestData: Data?
    private var stopWork: DispatchWorkItem?
    private var bgTask: UIBackgroundTaskIdentifier = .invalid

    private static let p12Password = "buildbox-installer"
    // Publicly-trusted wildcard cert (*.localhost.direct, Let's Encrypt);
    // the domain resolves to 127.0.0.1, so installd sees a normal public
    // HTTPS host served by this phone. No user trust setup needed.
    static let installHost = "buildbox.localhost.direct"

    // MARK: - Public API

    /// Stop any in-progress install (the UI's Cancel button).
    static func cancelActiveInstall() {
        activeInstall?.stop()
        activeInstall = nil
    }

    static func install(ipaURL: URL, bundleID: String, appName: String, version: String,
                        progress: @escaping (String) -> Void,
                        completion: @escaping (Result<Void, Error>) -> Void) {
        progress("Installing...")
        let installer = LocalInstaller()
        activeInstall?.stop()
        activeInstall = installer
        installer.ipaFileURL = ipaURL
        installer.logHandler = { progress($0) }

        let identity: SecIdentity
        do {
            identity = try loadInstallerIdentity()
        } catch {
            completion(.failure(error))
            return
        }

        installer.bgTask = UIApplication.shared.beginBackgroundTask(withName: "BuildBoxInstall") {
            installer.stop()
        }

        do {
            try installer.startTLS(identity: identity) { port in
                installer.manifestData = generateManifest(
                    port: port, bundleID: bundleID, appName: appName, version: version)
                progress("Local install server ready (port \(port))")
                installer.selfTest(port: port) { ok, detail in
                    progress(ok ? "Self-test OK: local HTTPS responds"
                                : "Self-test FAILED: \(detail)")
                    progress("Opening installer...")
                    let encoded = "https://\(installHost):\(port)/manifest.plist"
                        .addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(.init(charactersIn: "-._~"))) ?? ""
                    guard let url = URL(string: "itms-services://?action=download-manifest&url=\(encoded)") else {
                        completion(.failure(installError(8, "Invalid install URL")))
                        return
                    }
                    UIApplication.shared.open(url) { success in
                        if success {
                            completion(.success(()))
                        } else {
                            completion(.failure(installError(1, "Could not open installer")))
                        }
                    }
                    installer.scheduleStop(after: 300)
                }
            }
        } catch {
            completion(.failure(error))
        }
    }

    // MARK: - Server plumbing

    private func startTLS(identity: SecIdentity, onReady: @escaping (UInt16) -> Void) throws {
        let tlsOptions = NWProtocolTLS.Options()
        if let secIdentity = sec_identity_create(identity) {
            sec_protocol_options_set_local_identity(tlsOptions.securityProtocolOptions, secIdentity)
        }
        let params = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        try start(params: params, onReady: onReady)
    }

    private func startPlainHTTP(onReady: @escaping (UInt16) -> Void) throws {
        let params = NWParameters.tcp
        try start(params: params, onReady: onReady)
    }

    private func start(params: NWParameters, onReady: @escaping (UInt16) -> Void) throws {
        params.allowLocalEndpointReuse = true
        let listener = try NWListener(using: params, on: NWEndpoint.Port(integerLiteral: 0))
        self.listener = listener
        listener.newConnectionHandler = { [weak self] connection in
            self?.handle(connection)
        }
        listener.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                if let port = listener.port?.rawValue {
                    onReady(port)
                }
            case .failed(let error):
                print("[LocalInstaller] Listener failed: \(error)")
                self?.stop()
            default:
                break
            }
        }
        listener.start(queue: .global(qos: .userInitiated))
    }

    private func scheduleStop(after seconds: TimeInterval) {
        stopWork?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.stop() }
        stopWork = work
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds, execute: work)
    }

    func stop() {
        stopWork?.cancel()
        stopWork = nil
        listener?.cancel()
        listener = nil
        if bgTask != .invalid {
            UIApplication.shared.endBackgroundTask(bgTask)
            bgTask = .invalid
        }
    }

    // MARK: - Request handling

    private func handle(_ connection: NWConnection) {
        logHandler?("Connection attempt received")
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.logHandler?("Connection established (TLS OK)")
                self?.receiveRequest(on: connection)
            case .waiting(let error):
                self?.logHandler?("Connection waiting: \(error)")
            case .failed(let error):
                self?.logHandler?("Connection FAILED: \(error)")
            default:
                break
            }
        }
        connection.start(queue: .global(qos: .userInitiated))
    }

    private func receiveRequest(on connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] data, _, _, _ in
            guard let self = self, let data = data, !data.isEmpty,
                  let request = String(data: data, encoding: .utf8) else {
                connection.cancel()
                return
            }
            let firstLine = request.components(separatedBy: "\r\n").first ?? ""
            let parts = firstLine.components(separatedBy: " ")
            let method = parts.count > 0 ? parts[0] : "GET"
            let path = parts.count > 1 ? parts[1] : "/"
            let headOnly = (method == "HEAD")
            self.logHandler?("Served \(path)")

            if path == "/manifest.plist", let manifest = self.manifestData {
                self.send(connection, body: manifest, contentType: "application/xml", headOnly: headOnly)
            } else if path == "/app.ipa", let ipa = self.ipaFileURL {
                self.sendFile(connection, file: ipa, headOnly: headOnly)
            } else {
                self.send404(connection)
            }
        }
    }

    private func send(_ connection: NWConnection, body: Data, contentType: String, headOnly: Bool) {
        let header = "HTTP/1.1 200 OK\r\nContent-Type: \(contentType)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        var payload = Data(header.utf8)
        if !headOnly { payload.append(body) }
        connection.send(content: payload, contentContext: .finalMessage, isComplete: true,
                        completion: .contentProcessed { _ in })
    }

    private func sendFile(_ connection: NWConnection, file: URL, headOnly: Bool) {
        let size = (try? FileManager.default.attributesOfItem(atPath: file.path))?[.size] as? Int ?? 0
        let header = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: \(size)\r\nConnection: close\r\n\r\n"
        connection.send(content: Data(header.utf8), completion: .contentProcessed { [weak self] _ in
            guard !headOnly, let handle = try? FileHandle(forReadingFrom: file) else {
                connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                                completion: .contentProcessed { _ in })
                return
            }
            self?.sendChunks(connection, handle: handle)
        })
    }

    private func sendChunks(_ connection: NWConnection, handle: FileHandle) {
        let chunk = handle.readData(ofLength: 512 * 1024)
        if chunk.isEmpty {
            try? handle.close()
            connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                            completion: .contentProcessed { _ in })
            return
        }
        connection.send(content: chunk, completion: .contentProcessed { [weak self] error in
            if error != nil {
                try? handle.close()
                return
            }
            self?.sendChunks(connection, handle: handle)
        })
    }

    private func send404(_ connection: NWConnection) {
        let header = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        connection.send(content: Data(header.utf8), contentContext: .finalMessage, isComplete: true,
                        completion: .contentProcessed { _ in })
    }

    // MARK: - Identity + manifest

    private static func loadInstallerIdentity() throws -> SecIdentity {
        // Network.framework's TLS stack needs a keychain-backed identity; a
        // bare PKCS12 import can fail the handshake silently (Test4 evidence:
        // plain HTTP on 127.0.0.1 worked, HTTPS was unreachable even from
        // Safari). Prefer an identity already in the keychain.
        if let existing = keychainIdentity() { return existing }

        guard let url = Bundle.main.url(forResource: "installer", withExtension: "p12"),
              let data = try? Data(contentsOf: url) else {
            throw installError(11, "Installer certificate missing from app")
        }
        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: p12Password] as CFDictionary
        let status = SecPKCS12Import(data as CFData, options, &items)
        guard status == errSecSuccess,
              let arr = items as? [[String: Any]],
              let dict = arr.first,
              let raw = dict[kSecImportItemIdentity as String] else {
            throw installError(12, "Could not load installer identity")
        }
        let identity = raw as! SecIdentity

        // Persist cert + key into the keychain, then use the backed identity.
        var cert: SecCertificate?
        SecIdentityCopyCertificate(identity, &cert)
        if let cert = cert {
            SecItemAdd([kSecClass as String: kSecClassCertificate,
                        kSecValueRef as String: cert] as CFDictionary, nil)
        }
        var key: SecKey?
        SecIdentityCopyPrivateKey(identity, &key)
        if let key = key {
            SecItemAdd([kSecClass as String: kSecClassKey,
                        kSecValueRef as String: key,
                        kSecAttrApplicationLabel as String: "BuildBox localhost.direct"] as CFDictionary, nil)
        }
        return keychainIdentity() ?? identity
    }

    private static func keychainIdentity() -> SecIdentity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let arr = result as? [SecIdentity] else { return nil }
        for identity in arr {
            var cert: SecCertificate?
            SecIdentityCopyCertificate(identity, &cert)
            if let cert = cert,
               let summary = SecCertificateCopySubjectSummary(cert) as String?,
               summary.contains("localhost.direct") {
                return identity
            }
        }
        return nil
    }

    /// The app fetches its own manifest over HTTPS, trusting our cert.
    /// Distinguishes "TLS server broken" from "system clients reject us".
    private func selfTest(port: UInt16, done: @escaping (Bool, String) -> Void) {
        let delegate = SelfTestDelegate()
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        guard let url = URL(string: "https://\(LocalInstaller.installHost):\(port)/manifest.plist") else {
            done(false, "bad URL")
            return
        }
        let task = session.dataTask(with: url) { data, response, error in
            if let error = error {
                done(false, error.localizedDescription)
            } else if let http = response as? HTTPURLResponse {
                done(http.statusCode == 200 && (data?.count ?? 0) > 0,
                     "HTTP \(http.statusCode), \(data?.count ?? 0) bytes")
            } else {
                done(false, "no response")
            }
            session.finishTasksAndInvalidate()
        }
        task.resume()
    }

    private static func generateManifest(port: UInt16, bundleID: String, appName: String, version: String) -> Data {
        let ipaURL = "https://\(installHost):\(port)/app.ipa"
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>items</key>
            <array>
                <dict>
                    <key>assets</key>
                    <array>
                        <dict>
                            <key>kind</key>
                            <string>software-package</string>
                            <key>url</key>
                            <string>\(ipaURL)</string>
                        </dict>
                    </array>
                    <key>metadata</key>
                    <dict>
                        <key>bundle-identifier</key>
                        <string>\(bundleID)</string>
                        <key>bundle-version</key>
                        <string>\(version)</string>
                        <key>kind</key>
                        <string>software</string>
                        <key>title</key>
                        <string>\(appName)</string>
                    </dict>
                </dict>
            </array>
        </dict>
        </plist>
        """
        return plist.data(using: .utf8) ?? Data()
    }

    private static func installError(_ code: Int, _ message: String) -> NSError {
        NSError(domain: "BuildBox", code: code, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

/// Trusts the BuildBox installer certificate for the self-test only.
private class SelfTestDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
