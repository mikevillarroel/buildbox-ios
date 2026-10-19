# zsign Integration Feasibility Report (2026-10-17)

## Verdict: FEASIBLE — all technical paths proven working

## 1. What zsign is
- **zsign** (github.com/zhlynn/zsign, MIT license): C++11/17 cross-platform iOS code signer. ~15 source files.
- **Zsign-Package** (github.com/khcrysalis/Zsign-Package): fork with `package` branch adding SwiftPM support.
- **Swift API**: `Zsign.sign(appPath:provisionPath:p12Path:p12Password:...) -> Bool`
- **Key dependency**: OpenSSL 3.x via krzyzanowskim/OpenSSL SwiftPM package (prebuilt xcframework).
- zsign embeds Apple's CA certs (same approach as our Swift signer).

## 2. Toolchain findings
1. System clang++ 18 CANNOT compile C++ for Xcode 26.5 SDK (missing builtins). Use Swift toolchain's clang++ 21.
2. Linking: toolchain ld64.lld cannot link iOS, but system clang 18 + LLD 18 works (what ipab uses).
3. OpenSSL: krzyzanowskim/OpenSSL 3.6.5000, ios-arm64 slice is dynamic framework (7.2MB).
4. Swift bridging needs `-resource-dir $TC/darwin-res` (ipab already passes).

## 3. Required changes
**A. Vendor sources**: 14 files into BuildBox/src/zsign/, download OpenSSL.xcframework.zip
**B. ipab modifications**: 
  - Compile .cpp/.mm with toolchain clang++ 21
  - Keep link on system clang
  - Embed OpenSSL.framework, add -F and -framework flags
  - Ad-hoc sign framework with ldid
**C. App-side**: Bridging header, Swift wrapper (~60 lines), wire into SignView

## 4. Costs
- IPA size: +7.2MB (8.4MB → ~15.5MB)
- License: MIT, no GPL contamination
- Risk: LOW (KSign proves it works on-device)
