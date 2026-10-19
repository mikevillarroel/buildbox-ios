# BuildBox on-device signer — gap analysis vs working reference (2026-10-17)

Goal: make Test108+'s `signBinary` produce an installable signature. This analysis was
done by reading the reference implementation (Dadoum/Sideloader `source/sideload/sign.d`
+ `source/sideload/macho.d`, a real shipping sideloader) and by parsing real signed
binaries on the VM with Python. No theory — every gap below is checkable in code or
bytes.

## The working baseline (parsed from ESign-signed PosterBoard.app binaries)

Slot layout of the embedded superblob (magic 0xfade0cc0):
- slot 0 (0x0): CodeDirectory, blob magic 0xfade0c02, SHA-1 (hashSize 20, hashType 1), 4KB pages (log2 12), nSpecialSlots = 7
- slot 2: Requirements blob, magic 0xfade0c01
- slot 5: Entitlements, blob magic 0xfade7171
- slot 7: DER entitlements, blob magic 0xfade7172
- slot 0x1000: alternate CodeDirectory, SHA-256 (hashSize 32, hashType 2), 4KB pages, nSpecialSlots = 7
- slot 0x10000: CMS signature WRAPPED in a BlobWrapper (magic 0xfade0b01)

## What BuildBox emits today (MachOSigner.swift / IPASigner.swift)

1. **Entitlements blob magic is wrong** — `buildSuperBlob` tags slot 5 with `0xFADE0C05`.
   That magic is CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT, not CSMAGIC_EMBEDDED_ENTITLEMENTS
   (`0xFADE7171`). AMFI looks up slot 5 and validates magic 0xfade7171; the blob will
   not be recognized as entitlements.

2. **nSpecialSlots = 0** (`buildCodeDirectory`, line ~121). Reference/Apple use 7 for the
   main executable (slot contents, in order: hash(DER entitlements), empty, hash(XML
   entitlements), empty, hash(CodeResources), hash(requirements), hash(Info.plist))
   and 6 for other binaries (same minus the DER-entitlements slot). With 0 special
   slots, the entitlements/provisioning/Info.plist are not bound into the CodeDirectory,
   which is exactly the "integrity could not be verified" failure mode.

3. **Only one CodeDirectory (SHA-256 at slot 0)**. Apple writes SHA-1 at slot 0 and
   SHA-256 as the alternate at slot 0x1000. AMFI's cdhash logic keys off the primary
   SHA-1 directory; a lone SHA-256 primary is not what ESign/Apple produce.

4. **16KB pages (log2 14)** vs 4KB (log2 12) everywhere else. Apple's codesign default
   and zsign/Sideloader all use 4KB.

5. **CMS inserted raw** (no 0xfade0b01 BlobWrapper around the SignedData) — comment in
   `buildSuperBlob` claims this is "Apple convention" for CSSLOT_SIGNATURESLOT, but the
   reference wraps it, and every real signed binary shows the wrapper.

6. **CMS signedAttrs incomplete** (`createCMSSignature`): only contentType + messageDigest.
   Reference (matching Apple) also includes SigningTime and Apple's OIDs
   1.2.840.113635.100.9.2 (SHA-256 hash of the alternate CodeDirectory) and
   1.2.840.113635.100.9.1 (cdhashes plist: SHA-1-truncated cdhashes of all code dirs).

7. **SuperBlob missing slot 2 (Requirements) and slot 7 (DER entitlements)**. The main
   executable (MH_EXECUTE) needs the DER-entitlements blob; the CodeDirectory's special
   slots hash these blobs, so encode order matters: requirements + entitlements (+ DER
   entitlements) must be encoded BEFORE the CodeDirectory (reference enforces this).

## Why Test107 failed with "FAILED: Binary signing requires full Mach-O implementation"

That string is `SignError.signingNotFullyImplemented`, thrown at MachOSigner.swift:321:
`guard let (issuerDER, serialContent) = DER.extractIssuerAndSerial(from: certDER) else
{ throw ... }`. In Test107 `extractIssuerAndSerial` was STUBBED to return nil (disabled
while isolating the DER-parsing crash). Test108 re-enables it with the fixed DER
parsing, so that guard should pass — but the 7 format gaps above still stand between
Test108's output and an installable app.

## Fix order (smallest-risk first)

1. Entitlements blob magic 0xFADE0C05 → 0xFADE7171 (one constant).
2. Wrap CMS in BlobWrapper (0xfade0b01) in `buildSuperBlob`.
3. Add slot 2 (empty requirements blob, magic 0xfade0c01, length 12) and slot 7
   (DER entitlements, magic 0xfade7172) for MH_EXECUTE.
4. Rebuild `buildCodeDirectory` to take the encoded blobs and fill the 7/6 special
   slots (hash of DER entitlements, empty, hash of XML entitlements, empty,
   hash of CodeResources, hash of requirements, hash of Info.plist).
5. Emit both CodeDirectories: SHA-1 primary (slot 0), SHA-256 alternate (slot 0x1000).
6. Switch page size to 4KB (log2 12).
7. Add SigningTime + Apple 9.1/9.2 cdhash attributes to CMS signedAttrs.

## How to verify locally (no device needed)

Parse the produced binary with the same Python recipe used here (struct on
LC_CODE_SIGNATURE → superblob slots → CodeDirectory fields) and diff against the
ESign baseline slot layout above. Then have Miguel run his 3-step test plan.
