---
name: pb-windows-binary
description: Methodology playbook for analyzing Windows PE binaries (EXE/DLL/SYS, .NET assemblies) on a real target. Load when a Windows client, service, driver, or update is part of the attack surface and must be reasoned about as a binary, or when bb-next surfaces a binary-analysis test case.
---

# pb-windows-binary

## When this applies
Any Windows artifact you have to reason about as a binary rather than as source:
- A Windows PE file (EXE/DLL/SYS/driver) that is part of the target's attack surface — a client you can install, a service you can reach, a driver you can load, an update you can download.
- A Windows service, daemon, or scheduled task that parses network, file, or IPC input.
- A .NET assembly (dnSpy/ILSpy territory) shipped by the vendor.
- A protocol between a Windows client and server that you need to reconstruct from traffic plus disassembly.
- A memory-corruption, command-execution, privilege-escalation, information-disclosure, or denial-of-service question that can only be answered by reading or driving the binary.

If source is available for the same component, `pb-source-audit` is the cheaper, higher-signal first pass — use it before this playbook. Everything below assumes you cannot read the source.

## First signals
Notice these before you have any hypothesis about a bug:
- PE-header inspection shows a packer (UPX, Themida, VMP) or a suspiciously thin import table — a packed binary hides its imports and strings, which is itself a signal worth recording.
- The import table names a dangerous family: string copy without length (`strcpy`/`wcscpy`/`memcpy`), formatted output (`sprintf`/`printf`), command execution (`system`/`CreateProcess`/`ShellExecute`/`WinExec`), `LoadLibrary`/`GetProcAddress`, or `VirtualAlloc`/`HeapAlloc` — each family hints at a different bug class.
- The mitigation posture: `DllCharacteristics` and section flags showing which of ASLR/DEP/CFG/SafeSEH/GS exist. A binary with none of them is a different exploitation problem than one with all of them.
- Strings that look like leftovers: URLs, IPs, paths, `password=` keys, PDB paths, embedded SQL, error text that will echo internal state back to an attacker.
- A .NET binary that is obfuscated, or that names `Process.Start`, `XmlDocument.Load`, `BinaryFormatter`, `XmlSerializer`, or `RegEx` — the standard .NET bug classes map almost one-to-one onto those names.
- A program that behaves differently under a debugger than outside it (crashes, sleeps, exits, changes output) — anti-debugging code, which you must recognize before any dynamic step will make sense.

## Enumeration
Map the binary's full surface before hunting any single bug. This is a mapping pass, not a hunting pass.

1. Identify the artifact: language, compiler, packer, and architecture (DIE/PEiD/TrID, PE headers). This determines which toolchain applies.
   - Native (C/C++) → disassembler/decompiler path: IDA/Ghidra/Binary Ninja/Radare2.
   - .NET → decompiler path: dnSpy/ILSpy/dotPeek; de4dot first if obfuscated.
2. Read the PE structure: entry point, section permissions, mitigation flags, manifests, resources.
3. Enumerate imports and classify them by bug class — which sinks does this binary even have?
4. Extract strings and resources: URLs, IPs, paths, keys, SQL, error messages, embedded configs, certificates, PDB paths.
5. Enumerate the input surface: command line, config files, network sockets, named pipes, RPC/COM, registry values, and file formats the binary parses. The hunt follows input → sink paths.
6. For kernel components (SYS/drivers), the same path runs through IOCTL handlers — attacker-controlled `DeviceIoControl` buffers reaching copy/parse code, with kernel-specific sinks (pool allocation, arbitrary-write primitives).
7. For .NET, decompile and list every call into dangerous framework APIs; note the obfuscation state and whether strong-naming/signing blocks repackaging.
8. Run the binary once (or attach to it) under controlled conditions and watch what it connects to, writes, and logs — baseline its normal behavior before changing any input.
9. You've covered the surface when every input source is mapped to the sinks its data can reach, not when you've disassembled one interesting function.

## Test procedure
Work the two analysis paths in parallel — static to find candidate bugs, dynamic to confirm them — and confirm each tier of a finding before claiming it.

### Static path (native)
1. From each input source, trace data flow to a sink: where does the result of `recv`/`ReadFile`/`GetCommandLine` end up? Follow chains like `recv → memcpy`, `GetCommandLine → sprintf`, `ReadFile → strcpy` in the decompiler.
2. At each sink, ask the boundary question: is the copy length validated against the destination size, is the format string attacker-controlled, is the command string concatenated from input, is the file path user-shaped?
3. Classify what you find before trying to trigger it:
   - **Buffer overflow** — copy without length check: stack (strcpy/sprintf family), heap (memcpy into an undersized allocation), off-by-one loop conditions, integer overflow shrinking a size check, use-after-free.
   - **Command injection** — input reaching system/CreateProcess/ShellExecute via concatenation.
   - **Format string** — attacker-controlled format argument to printf/sprintf family.
   - **Path traversal / arbitrary file** — user-shaped paths into CreateFile/WriteFile.
   - **DLL hijacking** — LoadLibrary with an unqualified name in a writable directory.
   - **Info disclosure** — hardcoded secrets, debug output, PDB paths, error messages echoing internal state.
   - **DoS** — missing length validation, null dereference, divide-by-zero, unbounded loop on attacker-controlled state.
4. For each candidate, note the exact address, the function, and the condition under which the bug triggers.

### Static path (.NET)
5. Search the decompiled code for the .NET sink set: Process.Start (command injection), XmlDocument.Load (XXE), BinaryFormatter/XmlSerializer (deserialization), RegEx (ReDoS), path concatenation (traversal), hardcoded credentials.
6. If obfuscated, de4dot and re-decompile; record what the obfuscator protected, since that is often where the vendor thinks the sensitive logic lives.

### Dynamic path
7. Load the binary under a debugger (x64dbg/WinDbg) and set breakpoints at the dangerous APIs you found statically. Confirm the data actually reaches the sink with attacker-controlled content — static suspicion is not a bug until observed.
8. Watch what changes when your input changes: breakpoint hit counts, argument values, buffer contents. A sink that fires with your bytes in `src` and a length you control is a live candidate.
9. Hook (Frida/API Monitor) instead of breakpointing when the process is hostile to debuggers — same observation, lower footprint.
10. For crashes, capture the full state at fault: registers, stack, the crashing instruction, and which input bytes ended up where.

### Protocol reversing
11. If the bug surface is a protocol, capture live traffic (Wireshark) and correlate it with the parsing code: breakpoint at recv/WSARecv, then replay one captured packet and watch which fields the parser reads.
12. Identify the protocol's structural fields — length, magic, checksum — and build the smallest structurally-valid message you can mutate one field at a time.
13. Fuzz the parser: pick a harness (WinAFL for file formats, boofuzz for protocols), seed with valid samples, monitor for crashes, and dedupe crashes by stack hash.

### Anti-debugging and anti-VM recognition
14. Before trusting any dynamic observation, check for anti-analysis behavior: IsDebuggerPresent/CheckRemoteDebuggerPresent, PEB.BeingDebugged, timing checks (rdtsc/GetTickCount), hardware-breakpoint register checks (Dr0–Dr7), INT 3/INT 2D probes; and anti-VM signals (CPUID hypervisor bit, VMware/VBox registry, MAC, or process markers).
15. Neutralize at the branch level — hide the debugger (ScyllaHide) or patch the anti-debug branch — and re-run to confirm the behavior you saw was the real code path, not the detection path. For packed binaries, locate the OEP and dump the unpacked image before static work.

### Confirming a finding tier-by-tier
Each tier has its own evidence bar; never skip one.
- **Tier 1 — trigger**: a crafted input provably causes the fault (crash, hang, wrong behavior) and reproduces from a minimal input.
- **Tier 2 — control**: the fault overwrites a return address or function pointer, and a cyclic pattern shows exactly which offset controls EIP/RIP. This is what separates "it crashed" from "it is a memory-corruption primitive."
- **Tier 3 — execution**: you control where execution goes next; the binary's mitigations (DEP/ASLR/CFG) determine what work remains (an info leak for ASLR, a ROP chain for DEP).
- **Tier 4 — effect**: the controlled execution produces the claimed impact — a command run, a write, a read, a privilege change — observed end-to-end, not inferred.
- Where Tier 3–4 would need a ROP chain or shellcode, this playbook stops at the methodology: describe what the payload must accomplish and what observable outcome confirms it (callback received, file written, token changed). Never produce working shellcode or exploit bytes — confirm the tier with the simplest benign proof possible, or stop at the tier the program accepts.
- PoC construction is the packaging of Tiers 1–2: minimal input, deterministic run, expected output — nothing beyond what the tier evidence requires.

### Worked example of tiering a result
```
Input:  5000-byte packet to the config-parser service
Result: crash at 0x004013a7, EIP = 0x41414141 (bytes from the input)
        -> Tier 1 confirmed (reproducible crash), Tier 2 plausible but not yet proven
Input:  cyclic pattern payload, then exact-offset payload
Result: EIP = bytes from offset 260 of the input, ESP points into a buffer you control
        -> Tier 2 confirmed (precise control) — still Tier 2, NOT code execution
```
Report exactly the tier reached. "EIP controlled" is a memory-corruption finding, not RCE; "RCE" requires Tier 4 observed.

## Evidence to capture
- Binary identity: SHA-256, exact version/build, where you obtained it, and the file-type/packer identification output.
- The mitigation posture: ASLR/DEP/CFG/SafeSEH/GS state of the affected module — severity depends on it.
- The vulnerable site: function name/address, a disassembly/decompiler snippet of the sink, and the input → sink path that reaches it.
- The trigger: the minimal input that reproduces the fault and the exact conditions (environment, service state, one-shot vs. repeatable).
- The fault state: crash address, register/stack dump, and the pattern offset if control was demonstrated.
- For each tier claimed, the observation that proves it — never the tier name alone.
- For EoP: before/after privilege evidence (token/identity comparison). For info disclosure: the exact data type leaked and one redacted example.
- The PoC: a minimal script plus expected output, deterministic enough that a triager can rerun it.
- The environment: OS build, patch level, and whether the binary was patched/unpacked before analysis — all of it changes reproducibility.

## Escalation
- A crash alone (Tier 1) is a DoS at best and often Informative — escalate by proving control (Tier 2), then execution (Tiers 3–4). The gap between tiers is the actual work, not a formality.
- An info-disclosure bug escalates when it defeats a mitigation holding back a bigger bug — an address leak that breaks ASLR, a heap-layout leak, a leaked secret used by another component. Report the leak's role in the chain, not just the leak.
- Local-only impact (a bug in a client you run yourself) escalates when combined with a remote vector — a remote service, a malicious file opened by a victim, a UNC path. State the remote vector explicitly.
- A local privilege escalation (service path quoting, weak service ACL, DLL hijack, token abuse) escalates when you show a real privilege boundary crossed — low-privilege to SYSTEM with before/after evidence.
- .NET deserialization and command injection escalate fast once the sink is proven reachable with attacker input — the step from "sink exists" to "attacker controls the data reaching it" is the whole finding.
- Value the result the way triagers do: CVSS vectors (AV/AC/PR/UI/S/C/I/A) — a network-reachable, no-auth overflow is a different severity than a local, user-interaction one, even at the same tier.
- A protocol you reversed is itself a deliverable — even with no bug yet, the field map, checksum rules, and parser structure make future fuzzing targets concrete.

## Out-of-scope traps
- Do not run, debug, or fuzz a binary you are not authorized to run — "it was downloadable" is not authorization, and malware-adjacent samples are commonly out of scope. Check the program rules before executing anything.
- "It crashed" is not "RCE" — a crash whose EIP is not attacker-controlled is a DoS claim at best. Never round a Tier 1 observation up to memory corruption.
- EIP/RIP control (Tier 2) is still not code execution — DEP/ASLR/CFG may make the next step impractical, and many programs grade uncontrolled-overwrite findings below RCE.
- A dangerous API in the import table is not a vulnerability — the bug is the *unvalidated path* from attacker input to that API, which you must demonstrate, not infer.
- .NET decompilation revealing bad practice (concatenated SQL, a hardcoded key) is only reportable when reachable with attacker influence and impact — decompiler output alone proves nothing.
- Bugs in third-party components (a bundled DLL, a framework) usually belong to that vendor's program, not the target's — verify whose code the bug is in before filing.
- Info-disclosure findings that expose only the test environment or your own data are not impact.
- Stop at the tier the program needs to accept the report — do not weaponize further (no working shellcode, no real command execution against production, no persistence) to "prove" a finding the tiering already proves.
- A DoS demonstrated only on a program-provided dev instance, or one with no recovery story, may be downgraded — confirm the trigger and impact on the instance the program intends you to test.

## Integration
- Record every binary and input surface tested — including clean ones — with `mcp__bb__record_coverage`, noting the tier reached for each candidate, so the same DLL doesn't get re-analyzed next session.
- Bank half-results with `mcp__bb__add_primitive`: a crash without control, a hardcoded secret without a proven consumer, a reversed protocol field map with no bug yet, an anti-debug path that blocks dynamic work. These are exactly the partials this system keeps.
- When a finding is confirmed to the tier the program requires, route it through `bb-report` with the evidence package above — hash, mitigation posture, sink snippet, minimal reproducer, tier evidence.
- The assistant proposes which sinks to trace, which breakpoints to set, and which tier the current evidence supports; the human runs the debugger, sends the inputs, and confirms each tier observation. The assistant never asserts a tier the human hasn't observed.
- When source is available for the component, stop and cross-reference `pb-source-audit` first — findings confirmed there don't need re-confirmation here, and the source pass usually finds the same bug cheaper.
