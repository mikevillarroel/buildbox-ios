# BuildBox Test87 — Miguel's two UX fixes + the ZIP-decoder fix (saved tonight, build tomorrow morning)

Miguel said "seguimos manana" (2026-10-16 ~20:49 UTC) and asked to save two BuildBox
items for tomorrow. Both are **already implemented in source tonight** and syntax-checked,
plus the research stage fixed the nested-ZIP decoder that was blocking test 1.
Remaining tomorrow: build the Test87 ZIP + IPA and hand it to him when he resumes.

## Fix 1 — "Continue to Sign" jumps to the Sign tab (his bug report)

What he said (2026-10-16 21:26 UTC): after Compile, tapping "Continue with signing"
stayed inside the Compile tab doing the signing, while the real Sign tab sat empty —
"como que se queda haciendo signing, pero el tab es el de compile, no pasa al tab de signing."

Root cause: the button was a `NavigationLink` pushing a second `SignView` inside the
Compile tab's navigation stack — two Sign UIs, one in the wrong tab.

Fix (in source now):
- `CompilerApp.swift`: `ContentView` holds `@State selectedTab` + `@State pendingSignIpa`,
  `TabView(selection:)` with tags 0–3.
- `CompileView.swift`: "Continue to Sign →" is now a plain button that sets
  `pendingSignIpa = ipaURL` and flips `selectedTab = 1` (Sign tab).
- `SignView.swift`: `initialIpaURL` removed (was only used by the old NavigationLink);
  new `@Binding pendingSignIpa` consumed once in `onAppear` into `ipaURL`, then cleared.
  The Sign tab still starts blank when opened directly (Import IPA flow unchanged).

## Fix 2 — small Clear button on the Compile tab (his request)

What he said (2026-10-16 21:28 UTC): add a small Clear button on the Compile screen,
uncluttered — "reduce todo lo demás botones para que el botón clear quede" — so he can
clean up after a compile + export.

Fix (in source now):
- Replaced the full-width blue "Copy Log" with the same small centered row the Sign tab
  already uses: **Copy Log** (`PressableSmallGreenButtonStyle`) + **Clear**
  (`PressableSmallRedButtonStyle`), side by side, centered. No other buttons touched —
  this kept it uncluttered without resizing everything.
- `clearCompileState()` clears `buildLog`, `compileStatus`, `ipaURL`. Source code,
  imported ZIP and project name are KEPT on purpose so he can recompile without re-importing.

## Fix 3 — ZIP decoder now handles GitHub Actions artifacts (research-stage fix, tonight)

What was happening: signing a fresh Compile-tab IPA failed with "Corrupt ZIP file"
even after Test86's nested-IPA detection, because the OUTER artifact ZIP from GitHub
Actions uses **data descriptors** (general-purpose bit 3: sizes are 0 in the local
header, real sizes only in the central directory). The hand-rolled parser walked local
headers, read compSize=0, landed mid-data, and broke out extracting nothing.

Fix (in `IPASigner.swift` tonight): `unzipData` now parses the **central directory**
(EOCD → central dir entries → true sizes/methods/local-header offsets) instead of
walking local headers. Also added a `..` path-traversal guard on entry names.

Verified tonight with the real files, compiled with Swift 6.4.1 on the VM
(`~/workspace/xtool/swift-6.4.1-RELEASE-ubuntu24.04/usr/bin/swiftc`):
- `BuildBox-unsigned-2.ipa` (the failing nested ZIP) → extracts `BuildApp-unsigned.ipa`
- `BuildApp-unsigned-inner.ipa` and `RespringApp_fix.ipa` → byte-identical to Python
  zipfile reference extraction (`diff -r` clean on all three)
- a non-ZIP file still throws `SignError.corruptZip` correctly

This unblocks Miguel's test 1 tomorrow (compile → export unsigned IPA → sign in ESign)
without the manual Mac-extraction workaround.

## Known open issue (not requested tonight — assistant's standing task)

## Tomorrow morning

1. Syntax already verified: `~/workspace/xtool/syntax_check.sh ~/workspace/iphone-compiler-app/Sources` → all pass.
2. Build Test87 (increment per his test-numbering rule — latest is Test86) and hand him the ZIP/IPA.
3. Tell him all three fixes are in: Continue to Sign now lands in the Sign tab with the fresh
   IPA loaded; Clear button on Compile; and the GitHub Actions ZIP now decodes (no more
   manual Mac extraction needed for test 1).
4. Miguel's test order for tomorrow (he sent it 2026-10-16 22:08 UTC — "orden de los test
   de manana"):
   1. Compile + export unsigned IPA → sign it in ESign → install. (Proves the pipeline IPA is good.)
   2. Sign that IPA with BuildBox → export → install WITHOUT signing again in ESign.
      This is the moment of truth for the Mach-O signature work (Test51–58, Test84) —
      if iOS throws an integrity error, the binary signature still isn't valid; fall back
      to ESign re-sign of the same IPA to confirm the IPA itself is fine.
   3. Try installing inside BuildBox (Install-after-signed toggle) — only meaningful if
      test 2's signature passes.
5. No decoder workaround needed anymore; the inner-IPA file at
   `~/workspace/your_files/BuildApp-unsigned-inner.ipa` remains as a spare.
