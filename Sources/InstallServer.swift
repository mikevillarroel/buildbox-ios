import Foundation
import Network

// MARK: - Local HTTP server for itms-services installation
// Serves the signed IPA and manifest.plist so iOS can install via itms-services://

class InstallServer {
    private var listener: NWListener?
    private var ipaData: Data?
    private var manifestData: Data?
    private let port: NWEndpoint.Port
    
    init(port: UInt16 = 8765) {
        self.port = NWEndpoint.Port(integerLiteral: port)
    }
    
    func start(ipaURL: URL, bundleID: String, appName: String, version: String) throws {
        self.ipaData = try Data(contentsOf: ipaURL)
        self.manifestData = generateManifest(bundleID: bundleID, appName: appName, version: version)
        
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        listener = try NWListener(using: params, on: port)
        
        listener?.newConnectionHandler = { [weak self] connection in
            self?.handleConnection(connection)
        }
        listener?.stateUpdateHandler = { state in
            print("[InstallServer] State: \(state)")
        }
        listener?.start(queue: .global())
    }
    
    func stop() {
        listener?.cancel()
        listener = nil
    }
    
    var manifestURL: URL? {
        return URL(string: "http://127.0.0.1:\(port)/manifest.plist")
    }
    
    var installURL: URL? {
        guard let manifest = manifestURL else { return nil }
        let urlString = "itms-services://?action=download-manifest&url=\(manifest.absoluteString)"
        return URL(string: urlString)
    }
    
    private func generateManifest(bundleID: String, appName: String, version: String) -> Data {
        let ipaURL = "http://127.0.0.1:\(port)/app.ipa"
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
    
    private func handleConnection(_ connection: NWConnection) {
        connection.stateUpdateHandler = { [weak self] state in
            if state == .ready {
                self?.receiveRequest(on: connection)
            }
        }
        connection.start(queue: .global())
    }
    
    private func receiveRequest(on connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, isComplete, error in
            guard let self = self, let data = data, !data.isEmpty else {
                connection.cancel()
                return
            }
            
            let request = String(data: data, encoding: .utf8) ?? ""
            let path = self.extractPath(from: request)
            
            var responseData: Data?
            var contentType = "application/octet-stream"
            
            if path == "/manifest.plist" {
                responseData = self.manifestData
                contentType = "application/xml"
            } else if path == "/app.ipa" {
                responseData = self.ipaData
                contentType = "application/octet-stream"
            }
            
            if let body = responseData {
                let header = "HTTP/1.1 200 OK\r\nContent-Type: \(contentType)\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
                var response = Data(header.utf8)
                response.append(body)
                connection.send(content: response, completion: .contentProcessed { _ in
                    connection.cancel()
                })
            } else {
                let header = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                connection.send(content: Data(header.utf8), completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }
    }
    
    private func extractPath(from request: String) -> String {
        let lines = request.components(separatedBy: "\r\n")
        guard let firstLine = lines.first else { return "/" }
        let parts = firstLine.components(separatedBy: " ")
        guard parts.count >= 2 else { return "/" }
        return parts[1]
    }
}
