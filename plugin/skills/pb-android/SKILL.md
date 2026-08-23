---
name: pb-android
description: Methodology playbook for Android APK component security. Load when an APK (app, preinstalled, or vendor system app) is in scope and you need component-level hunting — exported components, Intents, WebView/JSBridge, ContentProvider, deep links, hardcoded keys to unauthorized backends — with verification that needs no root or Frida.
---

# pb-android

## When this applies
- You have an APK that is part of the program's scope: a normal app, a preinstalled app, or a vendor system app (settings, security center, engineering mode, OTA, diagnostics).
- The hunt is component security: exported Activities/Services/Receivers/Providers, Intent redirection, WebView/JSBridge, ContentProvider/Binder surfaces, deep links.
- The high-value path is key tracking → unauthorized backend calls: appId/appKey/signing secrets extracted from DEX/SO/H5, then used against the backend interface.
- Verification must work without root and without Frida as the exploit vehicle (ADB + a PoC app + a crafted HTML page are the legitimate vehicles).

Division of labor: getting the APK *unpacked* (packer identification, deobfuscation, full artifact set) is `pb-apk-reversing` — run it first when JADX shows stub classes. Miniprograms sharing the backend are `pb-miniprogram`. Refer to OWASP MASTG for the platform reference material this playbook compresses.

## First signals
- `android:exported="true"` on components that don't need it — especially with intent-filters, grant-uri-permissions, or no permission protection.
- Code reading Intents and passing fields straight into `startActivity`, `loadUrl`, `setText`, or file paths — external input driving internal capability.
- `addJavascriptInterface` bridges exposing methods to WebView content; `setAllowFileAccess`/`setAllowUniversalAccessFromFileURLs` enabled.
- ContentProvider `query`/`openFile` implementations without caller checks or path validation.
- Hardcoded secrets: `appKey`/`appSecret`/`secret`/`access_key`/`secret_key` strings, especially next to signing logic the backend verifies.
- Deep links (scheme://host/path in intent-filters) that route into privileged activities.
- A `getWXContext`-style identity assumption, or a backend that trusts a signed request because the signature was computed by *the app* rather than a server-held secret — the app-held secret is extractable by design.

## Enumeration
The workflow is static analysis (JADX) → dynamic verification (ADB), with the output feeding the standard backend playbooks.

1. Decompile (JADX + apktool; hand off to pb-apk-reversing if the app is packed) and confirm you see real business code, not stubs.
2. Manifest pass: list every exported component, its intent-filters, and its permission requirements. Components exported without permission and without a caller check are the shortlist.
3. Key-tracking pass (highest priority — this is where Android bounties concentrate):
   - DEX layer: grep for `appKey|appSecret|secret|sign|md5|encrypt|aes|rsa` and follow each hit to where the value is used — a hardcoded signing key means you can forge signed requests to the backend.
   - SO layer: for native signing/encryption (JNI exports `Java_`-prefixed or `RegisterNatives`-registered), note that the key is extractable by static analysis of the .so or by observing the signed request in transit; the *PoC* then uses the extracted key directly (Python/curl), never Frida.
   - H5/JS layer: WebView-loaded assets with embedded keys/endpoints.
4. Component-surface pass, per class:
   - **Intent redirection**: does an exported component take a nested Intent from the caller and start it? Does any component trust `getIntent()` fields (title/message/URL) into UI (dialog spoofing on system apps)?
   - **Deep links**: what paths route where, and can a crafted link drive a privileged activity or inject into a WebView (`loadUrl` with intent data)?
   - **ContentProvider**: `query`/`openFile`/`openAssetFile` — caller checks, path traversal in file URIs, grant-uri-permissions leaks.
   - **WebView/JSBridge**: JavaScript enabled with interfaces to sensitive methods; file access enabled; unsafe schemes allowed.
   - **Broadcast receivers**: exported receivers acting on unvalidated broadcasts (a state-changing receiver callable by any app).
   - **Binder services** (system apps): exported AIDL interfaces with privileged operations and no caller-uid check.
   - **Command execution**: `Runtime.exec`/`ProcessBuilder` with any remotely-influenceable input.
5. Extract assets: every URL/IP/domain (backend hosts — usually weaker auth than the web frontend), every appid/appkey (report them and test what they unlock — cloud services, push, maps).
6. You've covered the APK when each exported component has a caller-check verdict and each hardcoded secret has a consumer identified.

## Test procedure
1. Key → unauthorized interface (the flagship path): extract the key and the signing/encryption scheme, reimplement the signed request in a script, and call the backend interface with the forged signature. Confirmation: the backend accepts the forged request and returns data or performs the action. The report story is *hardcoded key + interface not checking anything beyond the signature* — no Frida appears anywhere.
2. Remote-vs-local grading: for every candidate, determine whether an attacker needs to install an app / touch the device (local) or can trigger it via link/message/web (remote). Remote triggers rate higher — a deep link or an exported receiver reachable from a browser or messaging app is the escalation to chase.
3. Intent redirection: from your own PoC app, send the nested Intent to the exported component and observe whether the inner Intent executes (an activity you shouldn't reach starts, or its result comes back). Confirmation is the privileged behavior actually happening.
4. ContentProvider: query through the exported provider for rows you shouldn't see; openFile with `../`-style paths for files outside the intended root. Confirmation is the data/file actually returned.
5. WebView/JSBridge: load a page you control inside the vulnerable WebView (via deep link or a file the app opens) and call the bridged methods; confirmation is the bridged capability executing from your page.
6. Deep-link driven UI injection on system apps: a link carrying the dialog title/message reaching a trusted system dialog — confirmation is the spoofed dialog rendering with attacker text (a social-engineering primitive on system apps).
7. Dynamic verification without root/Frida: `adb shell am start` with crafted extras for intent paths; a small PoC app for provider/service/binder paths; a crafted HTML page for WebView/deep-link paths. Frida may be used only as a *forensic* aid for key/signature tracing — never as part of the PoC.
8. Severity estimation against the vendor-SRC standard the program uses (the vendor bug-bounty programs' mobile acceptance tiers and ignore lists): remote > local, preinstalled/system > third-party app, and the program's ignore list decides what isn't worth reporting (see Out-of-scope traps).

### Worked example
```
Static:  appKey="9f8..." hardcoded; backend verifies only md5(params + appKey)
PoC:     script recomputes the signature with the extracted key
Confirm: backend /api/order/export?sign=... returns order data → forged request accepted
         -> hardcoded key + weak interface auth confirmed
```
The finding is the extractable key plus the interface trusting it — one without the other is a lead, not a finding.

## Evidence to capture
- The APK hash/version/channel (vendor programs usually want the latest store version).
- For each finding: the decompiled fragment with file path, the vulnerability type, the attack vector (remote/local), and the rating rationale.
- For key findings: the extracted key material (redacted in evidence; the program gets it in the report context), the reimplemented signature logic, and the backend response proving acceptance.
- For component findings: the PoC app/page used, the `adb` command or trigger link, and the observed privileged behavior.
- Before/after pairs wherever a check exists on one path and not another (a component variant with and without the caller check).

## Escalation
- A hardcoded key escalates by what it unlocks: read-only data < write operations < admin functions < cross-tenant data. Test the interface's actual authorization surface before claiming impact.
- Local-only findings escalate when a remote trigger is found — the deep link, browser-reachable receiver, or message-driven intent that removes the "attacker must install an app" assumption.
- An exported provider leaking one file escalates when the path traversal reaches beyond the intended root (database, shared prefs, other apps' sandboxes).
- A WebView bridge method escalates by what the bridged method does — reading a file vs executing a command vs installing something.
- System-app dialog spoofing escalates when the spoofed dialog can drive a real user decision (granting a permission, confirming a payment) — the impact is the deceived action, not the dialog.
- Backend hosts extracted from the APK feed the standard playbooks (pb-api-security, pb-idor-bola, pb-cloud-infra) — the Android finding is often just the *entry* to a web finding.

## Out-of-scope traps
- Respect the program's ignore list: Frida/hook-dependent exploitation, root-required exploits, and self-app-only impact are commonly excluded — know the list before spending days.
- grep hits are not findings: a dangerous call exists in code only matters with a reachable, exported, unvalidated path to it — verify reachability every time.
- Don't fabricate file names or line numbers — evidence must come from actual JADX/ADB output; invented details die at bb-gate.
- Backend abuse with a leaked key must stay inside the program's rules — confirming the key works is enough; don't mass-export data with it.
- Local storage of sensitive data by the app (plaintext tokens) is usually low/Informative — don't inflate it.
- Third-party SDK bugs (a bundled analytics SDK's exported component) belong to the SDK vendor's program — attribute the component's package before filing.
- Testing preinstalled/system apps needs the device the program provides or authorizes — don't root or flash your way into a test environment outside their terms.

## Integration
- Record each component and key-tracking path tested with `mcp__bb__record_coverage`, including clean results, so the same APK isn't re-audited next session.
- Bank primitives with `mcp__bb__add_primitive`: extracted keys without a confirmed consumer, exported components with no proven path, backend hosts discovered but untested.
- Extracted endpoints/domains go through bb-recon into the ledger; confirmed backend findings route to pb-api-security/pb-idor-bola; confirmed findings go through bb-gate into bb-report.
- The assistant proposes which component to test next and the exact ADB/PoC step; the human runs every command and confirms every observed behavior.
