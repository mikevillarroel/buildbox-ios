import SwiftUI
import UniformTypeIdentifiers
import UIKit
import Security

// MARK: - Certificate import, integrated into the Sign tab
// One-time setup: the user's .p12 + .mobileprovision live in Documents and
// persist across launches (names in AppStorage, password in UserDefaults —
// same keys the old Certificate tab used, so existing installs carry over).

struct CertificateSection: View {
    @AppStorage("certP12Name") private var storedP12Name = ""
    @AppStorage("certProvisionName") private var storedProvisionName = ""
    @AppStorage("hasCertificate") private var storedHasCert = false

    @State private var showingP12Picker = false
    @State private var showingRemoveConfirm = false
    @State private var showingProvisionPicker = false
    @State private var p12Name = ""
    @State private var provisionName = ""
    @State private var p12Password = ""
    @State private var p12URL: URL?
    @State private var provisionURL: URL?
    @State private var passwordError = ""

    var hasCertificate: Bool {
        p12URL != nil && provisionURL != nil && passwordError.isEmpty && !p12Password.isEmpty
    }

    private func saveCertificateState() {
        storedP12Name = p12Name
        storedProvisionName = provisionName
        storedHasCert = hasCertificate
    }

    private func validatePassword() {
        guard let url = p12URL else { return }
        guard let data = try? Data(contentsOf: url) else {
            passwordError = "Could not read certificate file"
            saveCertificateState()
            return
        }
        let options: [String: Any] = [kSecImportExportPassphrase as String: p12Password]
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &items)
        if status == errSecSuccess {
            passwordError = ""
            UserDefaults.standard.set(p12Password, forKey: "certP12Password")
        } else {
            passwordError = "Wrong password — try again"
        }
        saveCertificateState()
    }

    var body: some View {
        Section(header: Text("Certificate")) {
            if hasCertificate {
                HStack {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundColor(.green)
                    Text("Certificate ready")
                        .font(.subheadline)
                    Spacer()
                    Button("Remove", role: .destructive) {
                        showingRemoveConfirm = true
                    }
                    .foregroundColor(.red)
                    .alert("Remove Certificate?", isPresented: $showingRemoveConfirm) {
                        Button("Yes", role: .destructive) {
                            p12URL = nil
                            provisionURL = nil
                            p12Name = ""
                            provisionName = ""
                            p12Password = ""
                            storedP12Name = ""
                            storedProvisionName = ""
                            storedHasCert = false
                        }
                        Button("Cancel", role: .cancel) { }
                    } message: {
                        Text("Are you sure you want to remove the certificate? You will need to import it again to sign.")
                    }
                }
                HStack {
                    Image(systemName: "doc.fill")
                        .foregroundColor(.secondary)
                    Text(p12Name)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                HStack {
                    Image(systemName: "doc.fill")
                        .foregroundColor(.secondary)
                    Text(provisionName)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            } else {
                Text("One-time setup — like ESign: your .p12 certificate and .mobileprovision profile. They stay on this iPhone.")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Button(action: { showingP12Picker = true }) {
                    HStack {
                        Image(systemName: p12URL != nil ? "checkmark.circle.fill" : "doc.fill")
                            .foregroundColor(p12URL != nil ? .green : .blue)
                        Text(p12Name.isEmpty ? "Select .p12 Certificate" : p12Name)
                            .foregroundColor(.primary)
                        Spacer()
                        Image(systemName: "chevron.right")
                            .foregroundColor(.secondary)
                    }
                }

                if p12URL != nil {
                    SecureField("Certificate Password", text: $p12Password)
                        .onChange(of: p12Password) { _ in validatePassword() }
                    if !passwordError.isEmpty {
                        Text(passwordError)
                            .font(.caption)
                            .foregroundColor(.red)
                    } else if !p12Password.isEmpty {
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.green)
                            Text("Password correct")
                                .font(.caption)
                                .foregroundColor(.green)
                        }
                    }
                }

                Button(action: { showingProvisionPicker = true }) {
                    HStack {
                        Image(systemName: provisionURL != nil ? "checkmark.circle.fill" : "doc.fill")
                            .foregroundColor(provisionURL != nil ? .green : .blue)
                        Text(provisionName.isEmpty ? "Select .mobileprovision" : provisionName)
                            .foregroundColor(.primary)
                        Spacer()
                        Image(systemName: "chevron.right")
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .sheet(isPresented: $showingP12Picker) {
            DocumentPicker { urls in
                showingP12Picker = false
                if let url = urls.first {
                    let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
                    let dest = docs.appendingPathComponent(url.lastPathComponent)
                    try? FileManager.default.removeItem(at: dest)
                    if (try? FileManager.default.copyItem(at: url, to: dest)) != nil {
                        p12URL = dest
                    } else {
                        p12URL = url
                    }
                    p12Name = url.lastPathComponent
                    saveCertificateState()
                }
            }
        }
        .sheet(isPresented: $showingProvisionPicker) {
            DocumentPicker { urls in
                showingProvisionPicker = false
                if let url = urls.first {
                    let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
                    let dest = docs.appendingPathComponent(url.lastPathComponent)
                    try? FileManager.default.removeItem(at: dest)
                    if (try? FileManager.default.copyItem(at: url, to: dest)) != nil {
                        provisionURL = dest
                    } else {
                        provisionURL = url
                    }
                    provisionName = url.lastPathComponent
                    saveCertificateState()
                }
            }
        }
        .onAppear {
            // Restore persisted certificate files from Documents
            let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
            if !storedP12Name.isEmpty {
                let p12Path = docs.appendingPathComponent(storedP12Name)
                if FileManager.default.fileExists(atPath: p12Path.path) {
                    p12URL = p12Path
                    p12Name = storedP12Name
                }
            }
            if !storedProvisionName.isEmpty {
                let provPath = docs.appendingPathComponent(storedProvisionName)
                if FileManager.default.fileExists(atPath: provPath.path) {
                    provisionURL = provPath
                    provisionName = storedProvisionName
                }
            }
            // Imported certs persist: restore the saved password so the
            // section shows "ready" without re-typing (Miguel's rule).
            if p12Password.isEmpty,
               let saved = UserDefaults.standard.string(forKey: "certP12Password"),
               !saved.isEmpty {
                p12Password = saved
                validatePassword()
            }
        }
    }
}
