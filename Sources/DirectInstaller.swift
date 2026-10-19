import Foundation
import UIKit

// MARK: - Direct install via HTTPS + itms-services
// Uploads IPA to uguu.se (direct link), manifest via GitHub Gist (correct XML MIME type), then triggers iOS install dialog

class DirectInstaller {
    
    static func uploadAndInstall(ipaURL: URL, bundleID: String, appName: String, version: String,
                                 progress: @escaping (String) -> Void,
                                 completion: @escaping (Result<Void, Error>) -> Void) {
        
        progress("Installing...")
        
        // Upload IPA to transfer.sh
        uploadFile(ipaURL: ipaURL) { result in
            switch result {
            case .success(let ipaDownloadURL):
                // Upload manifest silently (don't reveal upload in log)
                
                // Generate manifest with the HTTPS URL
                let manifest = generateManifest(ipaURL: ipaDownloadURL, bundleID: bundleID, appName: appName, version: version)
                
                // Upload manifest
                uploadData(manifest, filename: "manifest.plist") { result in
                    switch result {
                    case .success(let manifestURL):
                        progress("Opening installer...")
                        
                        // Build itms-services URL with proper encoding
                        // Format: itms-services://?action=download-manifest&url=<encoded-manifest-url>
                        guard let encodedManifestURL = manifestURL.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(.init(charactersIn: "-._~"))) else {
                            completion(.failure(NSError(domain: "BuildBox", code: 8, userInfo: [NSLocalizedDescriptionKey: "URL encoding failed"])))
                            return
                        }
                        let installURLString = "itms-services://?action=download-manifest&url=\(encodedManifestURL)"
                        
                        if let installURL = URL(string: installURLString) {
                            DispatchQueue.main.async {
                                UIApplication.shared.open(installURL) { success in
                                    if success {
                                        completion(.success(()))
                                    } else {
                                        completion(.failure(NSError(domain: "BuildBox", code: 1, userInfo: [NSLocalizedDescriptionKey: "Could not open installer"])))
                                    }
                                }
                            }
                        } else {
                            completion(.failure(NSError(domain: "BuildBox", code: 8, userInfo: [NSLocalizedDescriptionKey: "Invalid install URL"])))
                        }
                    case .failure(let error):
                        completion(.failure(error))
                    }
                }
                
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    private static func uploadFile(ipaURL: URL, completion: @escaping (Result<String, Error>) -> Void) {
        // Use uguu.se (direct download links, required for itms-services)
        let uploadURL = URL(string: "https://uguu.se/upload.php")!
        
        var request = URLRequest(url: uploadURL)
        request.httpMethod = "POST"
        request.timeoutInterval = 180
        
        let boundary = "Boundary-\(UUID().uuidString)"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        
        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"files[]\"; filename=\"\(ipaURL.lastPathComponent)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: application/octet-stream\r\n\r\n".data(using: .utf8)!)
        
        guard let fileData = try? Data(contentsOf: ipaURL) else {
            completion(.failure(NSError(domain: "BuildBox", code: 5, userInfo: [NSLocalizedDescriptionKey: "Could not read IPA"])))
            return
        }
        body.append(fileData)
        body.append("\r\n--\(boundary)--\r\n".data(using: .utf8)!)
        
        request.httpBody = body
        
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 180
        config.timeoutIntervalForResource = 600
        let session = URLSession(configuration: config)
        
        let task = session.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let data = data else {
                completion(.failure(NSError(domain: "BuildBox", code: 2, userInfo: [NSLocalizedDescriptionKey: "Upload failed: no response"])))
                return
            }
            // Parse JSON: {"success":true,"files":[{"url":"https://..."}]}
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let files = json["files"] as? [[String: Any]],
               let first = files.first,
               let urlString = first["url"] as? String {
                completion(.success(urlString))
            } else {
                let raw = String(data: data, encoding: .utf8) ?? "unknown"
                completion(.failure(NSError(domain: "BuildBox", code: 7, userInfo: [NSLocalizedDescriptionKey: "Upload failed: \(raw.prefix(100))"])))
            }
        }
        task.resume()
    }
    
    private static func uploadData(_ data: Data, filename: String, completion: @escaping (Result<String, Error>) -> Void) {
        // Create a secret GitHub Gist with the manifest (correct MIME type for iOS)
        guard let token = GitHubKeychain.getToken() else {
            completion(.failure(NSError(domain: "BuildBox", code: 9, userInfo: [NSLocalizedDescriptionKey: "GitHub not connected"])))
            return
        }
        
        guard let manifestString = String(data: data, encoding: .utf8) else {
            completion(.failure(NSError(domain: "BuildBox", code: 10, userInfo: [NSLocalizedDescriptionKey: "Invalid manifest"])))
            return
        }
        
        let gistURL = URL(string: "https://api.github.com/gists")!
        var request = URLRequest(url: gistURL)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 30
        
        let body: [String: Any] = [
            "public": false,
            "description": "BuildBox install manifest",
            "files": [
                filename: ["content": manifestString]
            ]
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        
        let task = URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let files = json["files"] as? [String: Any],
                  let fileInfo = files[filename] as? [String: Any],
                  let rawURL = fileInfo["raw_url"] as? String else {
                completion(.failure(NSError(domain: "BuildBox", code: 4, userInfo: [NSLocalizedDescriptionKey: "Gist creation failed"])))
                return
            }
            completion(.success(rawURL))
        }
        task.resume()
    }
    
    private static func generateManifest(ipaURL: String, bundleID: String, appName: String, version: String) -> Data {
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
}
