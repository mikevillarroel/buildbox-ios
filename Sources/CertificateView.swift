import SwiftUI
import UniformTypeIdentifiers
import UIKit
import Security

struct CertificateView: View {
    @AppStorage("certP12Name") private var storedP12Name = ""
    @AppStorage("certProvisionName") private var storedProvisionName = ""
    @AppStorage("hasCertificate") private var storedHasCert = false
    
    @State private var showingP12Picker = false
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
            // Store password securely for signing (keychain would be better, using UserDefaults for now)
            UserDefaults.standard.set(p12Password, forKey: "certP12Password")
        } else {
            passwordError = "Wrong password — try again"
        }
        saveCertificateState()
    }
    
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                if hasCertificate {
                    HStack {
                        Image(systemName: "checkmark.seal.fill")
                            .foregroundColor(.green)
                        Text("Certificate ready")
                    }
                    .font(.headline)
                    
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Image(systemName: "doc.fill")
                            Text(p12Name)
                                .font(.caption)
                        }
                        HStack {
                            Image(systemName: "doc.fill")
                            Text(provisionName)
                                .font(.caption)
                        }
                    }
                    .foregroundColor(.secondary)
                    
                    Button("Remove Certificate", role: .destructive) {
                        p12URL = nil
                        provisionURL = nil
                        p12Name = ""
                        provisionName = ""
                        p12Password = ""
                        storedP12Name = ""
                        storedProvisionName = ""
                        storedHasCert = false
                    }
                    .buttonStyle(PressableRedButtonStyle())
                } else {
                    Image(systemName: "doc.badge.plus")
                        .font(.system(size: 60))
                        .foregroundColor(.secondary)
                    
                    Text("Import your signing files")
                        .font(.headline)
                    
                    Text("Like in ESign: your .p12 certificate and .mobileprovision profile. Each user brings their own.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                    
                    // P12 row
                    Button(action: { showingP12Picker = true }) {
                        HStack {
                            Image(systemName: p12URL != nil ? "checkmark.circle.fill" : "doc.fill")
                                .foregroundColor(p12URL != nil ? .green : .blue)
                            Text(p12Name.isEmpty ? "Select .p12 Certificate" : p12Name)
                            Spacer()
                            Image(systemName: "chevron.right")
                                .foregroundColor(.secondary)
                        }
                        .padding()
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(10)
                    }
                    .padding(.horizontal)
                    
                    // Password field (only shown when p12 is selected)
                    if p12URL != nil {
                        SecureField("Certificate Password", text: $p12Password)
                            .textFieldStyle(.roundedBorder)
                            .padding(.horizontal)
                            .onChange(of: p12Password) { _ in validatePassword() }
                        
                        if !passwordError.isEmpty {
                            Text(passwordError)
                                .font(.caption)
                                .foregroundColor(.red)
                                .padding(.horizontal)
                        } else if !p12Password.isEmpty {
                            HStack {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundColor(.green)
                                Text("Password correct")
                                    .font(.caption)
                                    .foregroundColor(.green)
                            }
                            .padding(.horizontal)
                        }
                    }
                    
                    // Mobileprovision row
                    Button(action: { showingProvisionPicker = true }) {
                        HStack {
                            Image(systemName: provisionURL != nil ? "checkmark.circle.fill" : "doc.fill")
                                .foregroundColor(provisionURL != nil ? .green : .blue)
                            Text(provisionName.isEmpty ? "Select .mobileprovision" : provisionName)
                            Spacer()
                            Image(systemName: "chevron.right")
                                .foregroundColor(.secondary)
                        }
                        .padding()
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(10)
                    }
                    .padding(.horizontal)
                }
                
                Spacer()
            }
            .padding()
            .navigationTitle("Certificate")
            .sheet(isPresented: $showingP12Picker) {
                DocumentPicker { urls in
                    showingP12Picker = false
                    if let url = urls.first {
                        // Copy to Documents for persistence
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
                        // Copy to Documents for persistence
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
        }
    }
}
