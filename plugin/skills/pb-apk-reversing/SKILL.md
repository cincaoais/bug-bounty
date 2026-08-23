---
name: pb-apk-reversing
description: Upstream preparation playbook for turning an APK into fully auditable artifacts. Load when JADX shows stub/empty classes, the entry class is a packer wrapper, or pb-android needs real code to work from. Produces packer identification → unpacking → decompiled source + resources + native libs + assets, and nothing else — bug hunting is pb-android's job.
---

# pb-apk-reversing

## When this applies
- JADX opened the APK but shows stub/empty classes instead of business code.
- The Application/entry class is a known packer wrapper (`com.stub.StubApp`, `com.secneo.apkwrapper`, …).
- `lib/` contains only packer .so files (libshella, libjiagu, libSecShell, …) and no real native code.
- You need the full artifact set — Java source, smali, .so files, H5/assets, signing material — as input for pb-android or pb-source-audit.
- An H5/uni-app hybrid (`assets/apps/<appid>/www/`) where the frontend source is extractable without any unpacking.

This playbook only *restores* code. It never hunts bugs and never rates findings — hand the artifact set to pb-android.

## First signals
- JADX output dominated by wrapper classes with no business logic.
- A small, suspicious `lib/` directory for an app that clearly has native features.
- Entry classes named after well-known packer vendors.
- `assets/apps/*/www/` present — a DCloud uni-app or similar hybrid; the web frontend is right there, no unpacking needed.
- Multiple dex files with damaged headers after a memory dump — the classic post-unpacking repair situation.

## Enumeration
1. Identify the packer (or confirm there is none): inspect `lib/` contents and the entry/Application class. The packer table below covers the common cases:

| Packer | Signature | Typical unpack route |
|---|---|---|
| Tencent Legu | libshella-*.so / libtprt.so / com.stub.StubApp | frida-dexdump, emulator runtime dump |
| Bangcle | libSecShell.so / SecShell | frida-dexdump, reflective dump tools |
| Ijiami | libexec.so / libexecmain.so / com.secneo.apkwrapper | frida-dexdump |
| 360 | libjiagu.so / libjiagu_x86.so | vendor unpack tools, reflective dump |
| Naga/Dingxiang | libchaosvmp.so / libddog.so | memory dump + dex repair |
| uni-app hybrid | no packer .so; assets/apps/\<appid\>/www/ present | no unpacking — extract www/ directly |

2. Decide the route: no packer → straight to decompilation; packer → unpack first; hybrid → extract the web root and skip the rest.
3. Collect the APK provenance: latest store version (vendor programs usually require it), channel/market variants (different channels can pack differently — switching channels is a legitimate shortcut).

## Test procedure
1. Obtain the APK: pull from an installed device (`adb shell pm path <pkg>` → `adb pull`), the vendor store, or the official site. Always note the exact version and channel.
2. Quick packer check: unzip-list the .so names and open the APK in JADX for a fast look at the Application class. Stub classes + packer .so = packed; real business classes visible = skip to step 6.
3. Unpack (packed APKs):
   - Preferred: rooted emulator + frida-server, install the app, launch it (the dex decrypts in memory only after launch), then dump the in-memory dex (frida-dexdump class tools). Multiple dex fragments → keep them all.
   - Damaged dump headers → repair with a dex-fix tool before decompiling.
   - Online unpacking services exist; only use them for targets you are authorized to test (uploading the APK is a data-handling decision).
   - Some legacy packers yield to `adb backup` extraction on older Android versions — worth one try when the emulator route is blocked.
4. Hybrid shortcut (uni-app and friends): unzip and take `assets/apps/*/www/` — that is the full frontend source; the "app" is a webview around it. No dex work needed for the H5 layer.
5. Decompile the (possibly unpacked) dex with JADX, and decode resources/Manifest with apktool. Extract `lib/` (arm64-v8a first) and `assets/` into the standard artifact layout.
6. Standard artifact layout for delivery:

```
reversing/<package>/
├── jadx_out/          # Java source — must be REAL code, not stubs
├── apktool_out/       # smali + resources + AndroidManifest
├── dex/               # unpacked dex (kept separately when not merged)
├── lib/               # all .so (arm64-v8a preferred, IDA/Ghidra-openable)
├── assets/            # H5/JS/certs/keys/config
├── origin.apk         # the original APK archive
└── report.md          # packer type / unpack route / artifact list / unresolved items
```

7. SO-layer preparation: in `lib/arm64-v8a/`, the JNI exports are the entry points — `Java_`-prefixed symbols (static registration) or `JNI_OnLoad`/`RegisterNatives` (dynamic). Static-first tooling: Ghidra (with the MCP bridge if available) for function listing and decompilation; Radare2 (`izz`/`afl`) as the lightweight fallback. Note which .so files resist static analysis (ollvm/VMP/string-encrypted) — those go to the dynamic path in pb-android, recorded honestly in report.md.
8. Quality gates before handing off:
   - JADX shows real business classes (not stubs).
   - `grep -rniE "appKey|secret|sign|api\\.|https?://" jadx_out/sources/` hits real strings.
   - `lib/arm64-v8a/` is complete and opens in a disassembler.
   - H5 in assets (or the remote load URLs) recorded.
   - All dex fragments merged, none dropped.
   - report.md written with the honest "not fully restored" list — never invent a clean handoff.

### Worked example
```
Check:   jadx_out shows only com.stub.StubApp wrappers; lib/ has libjiagu.so
         -> 360-packed → unpack route selected
Unpack:  emulator + frida-dexdump after launch → 3 dex fragments
Repair:  fragment 2 header damaged → dexfixer → all 3 decompile cleanly
Gate:    grep hits appKey/sign strings in restored sources → deliver to pb-android
```
The deliverable is the artifact set plus an honest report.md — that report is what keeps later findings attributable.

## Evidence to capture
- APK hash, version, channel, and acquisition route.
- Packer identification output (the .so names / entry class that decided the route).
- The artifact layout with sizes/hashes so downstream findings can cite the exact input.
- report.md contents: packer type, unpack method, artifacts, and the *unresolved* list.
- For hybrid apps: the extracted www/ tree hash.

## Escalation
- A fully restored artifact set escalates everything downstream: pb-android's key-tracking and component audits now have real code instead of stubs — the whole point of this playbook.
- An honestly recorded unresolved module (a VMP-protected .so) escalates into the dynamic path in pb-android rather than blocking — partial restoration with a clear map beats a fake complete one.
- New packer variants without a known tool route are research territory: note the packer's runtime behavior (where dex decrypts, when classes load) as a primitive for later sessions.
- Extracted H5/JS assets escalate straight into bb-code's endpoint/secrets extraction — the web surface inside the app is usually the fastest win.

## Out-of-scope traps
- Only reverse APKs you are authorized to test — the program's scope decides whether the APK is even in play.
- Online unpacking services mean uploading the target's binary to a third party — only for authorized targets, and prefer local tooling.
- Do not distribute or republish the decompiled code — the artifact set stays in your local working area, and report fragments are quoted, not attached wholesale.
- "JADX shows code" is not the same as "the real code" — packed apps can decompile partially; the stub-vs-real check is mandatory before any downstream finding.
- Unpacking tools that exploit packer vulnerabilities are themselves attack code — use them on your own authorized target only, and keep them out of the repo.
- report.md must stay honest — a fabricated "fully restored" note will poison every downstream finding's attribution.

## Integration
- The artifact set is the input for pb-android (component/key audit) and pb-source-audit (Java/so source audit) — hand it off with report.md attached.
- Extracted domains/keys/endpoints go through bb-recon into the coverage ledger as assets of the target.
- Record the APK in the ledger with `mcp__bb__record_coverage` (n-a for unpacked artifacts, or note the hash) so the same binary isn't re-reversed next session.
- Bank unresolved modules with `mcp__bb__add_primitive` — a VMP .so that needs the dynamic path is exactly the kind of half-result this system keeps.
- The assistant proposes the packer route and the quality gates; the human runs the unpacking tools and confirms each artifact is real.
