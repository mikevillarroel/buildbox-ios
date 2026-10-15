# BuildBox — iPhone Compiler & Signer

Compile Swift source into unsigned IPAs, sign them with your certificate, and install — all from your iPhone.

## Requirements

- iPhone with iOS 17.0 or later
- **GitHub account** (free) — required for compilation. Your code goes to your private repos; we never see it. Uses your free Actions minutes.
- Apple Developer certificate (.p12) + provisioning profile — for signing (import in the Certificate tab, ESign-style)

## How it works

1. **Compile tab**: Write or import Swift source. Connect your GitHub account (first requirement). Hit "Compile on Server" — your code is pushed to your private GitHub repo, compiled via GitHub Actions, and the unsigned IPA comes back to the app.
2. **Sign tab**: Select your imported certificate, fill in app details (pre-filled), hit the big blue Signature button. Or share the unsigned IPA.
3. **Certificate tab**: Import your .p12 and .mobileprovision (stored on-device only).
4. **About tab**: Developer info, social links, donate.

## Privacy

- Your GitHub token is stored in the iOS Keychain (secure, on-device only).
- Your source code goes only to your GitHub repos. We never see it.
- Your certificate never leaves your device.

## Build from source

Open `BuildBox.xcodeproj` in Xcode, select your team, build and run.
