import Foundation

// MARK: - GitHub Actions Build Service
// Handles: repo creation, source push, workflow trigger, status polling, IPA download

class GitHubService {
    static let shared = GitHubService()
    private init() {}
    
    private let apiBase = "https://api.github.com"
    
    private func request(_ path: String, token: String, method: String = "GET", body: Data? = nil) -> URLRequest {
        let url = URL(string: apiBase + path)!
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")
        if let body = body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = body
        }
        return req
    }
    
    // Create a private repo for the build
    func createRepo(name: String, token: String, completion: @escaping (Bool, String?) -> Void) {
        let body = try? JSONSerialization.data(withJSONObject: [
            "name": name,
            "private": true,
            "auto_init": false,
            "description": "BuildBox build repo — auto-created"
        ])
        let req = request("/user/repos", token: token, method: "POST", body: body)
        URLSession.shared.dataTask(with: req) { data, response, _ in
            let ok = (response as? HTTPURLResponse)?.statusCode == 201
            var repoName: String? = nil
            if ok, let data = data,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                repoName = json["full_name"] as? String
            }
            // 422 means repo already exists — that's fine
            let exists = (response as? HTTPURLResponse)?.statusCode == 422
            DispatchQueue.main.async {
                completion(ok || exists, repoName)
            }
        }.resume()
    }
    
    // Push a file via Contents API
    func pushFile(repo: String, path: String, content: String, token: String, message: String, completion: @escaping (Bool) -> Void) {
        // First get the SHA if file exists (for updates)
        let getReq = request("/repos/\(repo)/contents/\(path)", token: token)
        URLSession.shared.dataTask(with: getReq) { data, response, _ in
            var sha: String? = nil
            if (response as? HTTPURLResponse)?.statusCode == 200,
               let data = data,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                sha = json["sha"] as? String
            }
            
            var body: [String: Any] = [
                "message": message,
                "content": Data(content.utf8).base64EncodedString(),
                "branch": "main"
            ]
            if let sha = sha { body["sha"] = sha }
            
            let bodyData = try? JSONSerialization.data(withJSONObject: body)
            let putReq = self.request("/repos/\(repo)/contents/\(path)", token: token, method: "PUT", body: bodyData)
            URLSession.shared.dataTask(with: putReq) { _, response, _ in
                let ok = [200, 201].contains((response as? HTTPURLResponse)?.statusCode ?? 0)
                DispatchQueue.main.async { completion(ok) }
            }.resume()
        }.resume()
    }
    
    // Push binary data via Contents API
    func pushFileData(repo: String, path: String, data: Data, token: String, message: String, completion: @escaping (Bool) -> Void) {
        let fileData = data
        let getReq = request("/repos/\(repo)/contents/\(path)", token: token)
        URLSession.shared.dataTask(with: getReq) { respData, response, _ in
            var sha: String? = nil
            if (response as? HTTPURLResponse)?.statusCode == 200,
               let respData = respData,
               let json = try? JSONSerialization.jsonObject(with: respData) as? [String: Any] {
                sha = json["sha"] as? String
            }
            
            var body: [String: Any] = [
                "message": message,
                "content": fileData.base64EncodedString(),
                "branch": "main"
            ]
            if let sha = sha { body["sha"] = sha }
            
            let bodyData = try? JSONSerialization.data(withJSONObject: body)
            let putReq = self.request("/repos/\(repo)/contents/\(path)", token: token, method: "PUT", body: bodyData)
            URLSession.shared.dataTask(with: putReq) { _, response, _ in
                let ok = [200, 201].contains((response as? HTTPURLResponse)?.statusCode ?? 0)
                DispatchQueue.main.async { completion(ok) }
            }.resume()
        }.resume()
    }
    
    // Trigger the build workflow (with retry and diagnostics)
    func triggerBuild(repo: String, token: String, log: @escaping (String) -> Void, completion: @escaping (Bool) -> Void) {
        triggerBuildAttempt(repo: repo, token: token, attempt: 0, log: log, completion: completion)
    }
    
    private func triggerBuildAttempt(repo: String, token: String, attempt: Int, log: @escaping (String) -> Void, completion: @escaping (Bool) -> Void) {
        let body = try? JSONSerialization.data(withJSONObject: ["ref": "main"])
        let req = request("/repos/\(repo)/actions/workflows/build-ipa.yml/dispatches", token: token, method: "POST", body: body)
        URLSession.shared.dataTask(with: req) { data, response, _ in
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            if status == 204 {
                DispatchQueue.main.async { completion(true) }
            } else {
                DispatchQueue.main.async {
                    log("[BuildBox] Trigger attempt \(attempt + 1): HTTP \(status)")
                }
                if attempt < 5 {
                    // GitHub may need time to process the new workflow — wait and retry
                    // 404 = workflow not found yet, 422 = validation error
                    DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
                        self.triggerBuildAttempt(repo: repo, token: token, attempt: attempt + 1, log: log, completion: completion)
                    }
                } else {
                    DispatchQueue.main.async { completion(false) }
                }
            }
        }.resume()
    }
    
    // Get the latest workflow run status
    func getBuildStatus(repo: String, token: String, completion: @escaping (String?, String?, String?) -> Void) {
        let req = request("/repos/\(repo)/actions/runs?per_page=1", token: token)
        URLSession.shared.dataTask(with: req) { data, response, _ in
            var status: String? = nil
            var conclusion: String? = nil
            var runId: String? = nil
            if (response as? HTTPURLResponse)?.statusCode == 200,
               let data = data,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let runs = json["workflow_runs"] as? [[String: Any]],
               let run = runs.first {
                status = run["status"] as? String
                conclusion = run["conclusion"] as? String
                if let id = run["id"] as? Int { runId = String(id) }
            }
            DispatchQueue.main.async { completion(status, conclusion, runId) }
        }.resume()
    }
    
    // Get failed job logs for debugging
    func getFailureLogs(repo: String, runId: String, token: String, completion: @escaping (String?) -> Void) {
        let req = request("/repos/\(repo)/actions/runs/\(runId)/jobs?per_page=10", token: token)
        URLSession.shared.dataTask(with: req) { data, response, _ in
            var logText: String? = nil
            if (response as? HTTPURLResponse)?.statusCode == 200,
               let data = data,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let jobs = json["jobs"] as? [[String: Any]] {
                for job in jobs {
                    if let conclusion = job["conclusion"] as? String, conclusion == "failure",
                       let steps = job["steps"] as? [[String: Any]] {
                        var failedSteps: [String] = []
                        for step in steps {
                            if let stepConclusion = step["conclusion"] as? String,
                               stepConclusion == "failure",
                               let name = step["name"] as? String {
                                failedSteps.append(name)
                            }
                        }
                        if !failedSteps.isEmpty {
                            logText = "Failed steps: " + failedSteps.joined(separator: ", ")
                        }
                        break
                    }
                }
            }
            DispatchQueue.main.async { completion(logText) }
        }.resume()
    }
    
    // Download the full job logs (for debugging failures)
    func downloadJobLogs(repo: String, runId: String, token: String, completion: @escaping (String?) -> Void) {
        // First get the job ID
        let jobsReq = request("/repos/\(repo)/actions/runs/\(runId)/jobs?per_page=10", token: token)
        URLSession.shared.dataTask(with: jobsReq) { data, response, _ in
            var jobId: Int? = nil
            if (response as? HTTPURLResponse)?.statusCode == 200,
               let data = data,
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let jobs = json["jobs"] as? [[String: Any]],
               let job = jobs.first(where: { ($0["conclusion"] as? String) == "failure" }),
               let id = job["id"] as? Int {
                jobId = id
            }
            guard let jid = jobId else {
                DispatchQueue.main.async { completion(nil) }
                return
            }
            // Get the logs (returns plain text)
            let logReq = self.request("/repos/\(repo)/actions/jobs/\(jid)/logs", token: token)
            URLSession.shared.dataTask(with: logReq) { logData, logResp, _ in
                var logText: String? = nil
                if (logResp as? HTTPURLResponse)?.statusCode == 200,
                   let logData = logData {
                    logText = String(data: logData, encoding: .utf8)
                }
                DispatchQueue.main.async { completion(logText) }
            }.resume()
        }.resume()
    }
    
    // Download the IPA artifact
    func downloadIPA(repo: String, runId: String, token: String, completion: @escaping (URL?) -> Void) {
        let req = request("/repos/\(repo)/actions/runs/\(runId)/artifacts", token: token)
        URLSession.shared.dataTask(with: req) { data, response, _ in
            guard (response as? HTTPURLResponse)?.statusCode == 200,
                  let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let artifacts = json["artifacts"] as? [[String: Any]],
                  let artifact = artifacts.first(where: { ($0["name"] as? String)?.contains("ipa") ?? false }),
                  let downloadURL = artifact["archive_download_url"] as? String,
                  let url = URL(string: downloadURL) else {
                DispatchQueue.main.async { completion(nil) }
                return
            }
            
            var dlReq = URLRequest(url: url)
            dlReq.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            dlReq.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
            
            URLSession.shared.downloadTask(with: dlReq) { tempURL, _, _ in
                DispatchQueue.main.async { completion(tempURL) }
            }.resume()
        }.resume()
    }
    
    // The build workflow YAML (macOS + direct swiftc, no Xcode project needed)
    static var buildWorkflowYAML: String {
        return """
name: Build IPA
on:
  workflow_dispatch:
jobs:
  build:
    runs-on: macos-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      
      - name: Prepare source
        run: |
          mkdir -p BuildApp
          if [ -f source.zip ]; then
            echo "Unzipping source..."
            unzip -o source.zip -d BuildApp/
          elif [ -d src ]; then
            echo "Copying src/..."
            cp -r src/* BuildApp/ 2>/dev/null || true
          fi
          echo "Swift files:"
          find BuildApp -name "*.swift"
      
      - name: Compile with swiftc
        run: |
          SWIFT_FILES=$(find BuildApp -name "*.swift" | sort)
          if [ -z "$SWIFT_FILES" ]; then
            echo "ERROR: No Swift files found!"
            exit 1
          fi
          echo "Files to compile:"
          echo "$SWIFT_FILES"
          SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)
          echo "SDK: $SDK_PATH"
          swiftc --version
          echo "--- Compiling (errors will show below) ---"
          # shellcheck disable=SC2086
          swiftc -parse-as-library -target arm64-apple-ios17.0 -sdk "$SDK_PATH" -o BuildAppBinary $SWIFT_FILES -framework Foundation -framework UIKit -framework SwiftUI
          echo "Exit code: $?"
          ls -lh BuildAppBinary
          file BuildAppBinary
      
      - name: Package IPA
        run: |
          APP_NAME="BuildApp"
          BUNDLE_ID="com.buildbox.app"
          
          # Create app bundle
          mkdir -p "$APP_NAME.app"
          cp BuildAppBinary "$APP_NAME.app/$APP_NAME"
          
          # Create Info.plist
          cat > "$APP_NAME.app/Info.plist" << 'PLISTEOF'
          <?xml version="1.0" encoding="UTF-8"?>
          <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
          <plist version="1.0">
          <dict>
            <key>CFBundleIdentifier</key>
            <string>com.buildbox.app</string>
            <key>CFBundleName</key>
            <string>BuildApp</string>
            <key>CFBundleExecutable</key>
            <string>BuildApp</string>
            <key>CFBundleVersion</key>
            <string>1.0.0</string>
            <key>CFBundleShortVersionString</key>
            <string>1.0.0</string>
            <key>CFBundlePackageType</key>
            <string>APPL</string>
            <key>LSRequiresIPhoneOS</key>
            <true/>
            <key>UILaunchScreen</key>
            <dict/>
            <key>UISupportedInterfaceOrientations</key>
            <array>
              <string>UIInterfaceOrientationPortrait</string>
            </array>
          </dict>
          </plist>
          PLISTEOF
          
          # Package as IPA
          mkdir -p Payload
          cp -r "$APP_NAME.app" Payload/
          zip -r BuildApp-unsigned.ipa Payload/
          echo "IPA created:"
          ls -lh *.ipa
      
      - name: Upload IPA
        uses: actions/upload-artifact@v4
        with:
          name: app-ipa
          path: BuildApp-unsigned.ipa
"""
    }
}
