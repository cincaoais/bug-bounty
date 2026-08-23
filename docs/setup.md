# Setup — bb (bug bounty research assistant)

The parts only you can do, in order. Everything here runs on **your** machine, your
Claude Code, your Burp, your VM — that's why it can't be automated.

Legend: **[you, terminal]** run a command · **[you, Claude Code]** type in the Claude
Code prompt · **[you, GUI]** click through an app · ⚠️ = a step I could not test for you.

---

## 0. What you're installing

- A **local MCP server** (Python) that holds your case data in SQLite — no network, no LLM calls.
- **48 skills** (15 workflow + 33 vuln-class playbooks) that tell Claude how to drive it.
- A **PreToolUse hook** that hard-blocks out-of-scope commands.

It is **ingest-only**: it never sends traffic to a target. You run recon tools and browse;
it reads what you produce.

---

## 1. Prerequisites  [you, terminal]

You already have Python 3.13 and the `mcp` package (verified during the build). If you
ever move machines, the only install is:

```
python -m pip install mcp
```

Nothing else — the server is otherwise pure standard library.

---

## 2. Decide where case data lives  [you, terminal, optional]

By default, data goes to `~/.bb-bounty` (i.e. `C:\Users\Tang Cong Han\.bb-bounty`) —
deliberately **outside** this repo so it can't be committed. That's the safe default;
you don't need to change anything.

Only if you want it elsewhere, set an env var (PowerShell, permanent):

```
setx BB_DATA_DIR "D:\bb-data"
```

⚠️ Do **not** put it inside a git repo that has a remote. `health_check` (step 4) checks this.

Also: make sure `ANTHROPIC_API_KEY` is **not** set in your environment for this work.
If it is, Claude Code bills per-token instead of using your Pro/Max subscription. Check:

```
echo $env:ANTHROPIC_API_KEY
```

Empty output is what you want.

---

## 3. Install the plugin  [you, Claude Code]  ⚠️

This is the one step I couldn't test (no live plugin loader in my sandbox). Primary path:

```
/plugin marketplace add C:\Users\Tang Cong Han\Documents\GitHub\bug-bounty
/plugin install bb
```

Then restart Claude Code (or run `/plugin` and enable `bb` if it isn't active).

**If that errors** (the loader doesn't accept a local marketplace on your version), use
the fallback — wire the pieces directly, which is guaranteed to work:

1. **Skills** — copy `plugin\skills\*` into `C:\Users\Tang Cong Han\.claude\skills\`.
2. **MCP server** — [you, terminal]:
   ```
   claude mcp add bb -- python "C:\Users\Tang Cong Han\Documents\GitHub\bug-bounty\plugin\mcp\server.py"
   ```
3. **Hook** — add this to `C:\Users\Tang Cong Han\.claude\settings.json`:
   ```json
   {
     "hooks": {
       "PreToolUse": [
         { "matcher": "Bash",
           "hooks": [ { "type": "command",
             "command": "python \"C:\\Users\\Tang Cong Han\\Documents\\GitHub\\bug-bounty\\plugin\\hooks\\scope-guard.py\"" } ] }
       ]
     }
   }
   ```

Tell me which path worked and paste any error — the fallback is deterministic; we'll get it live.

---

## 4. Verify it loaded  [you, Claude Code]

1. `/bb:next` (or type `bb-next`) should be offered in the skill menu. If you see the
   `bb-*` skills, skills loaded.
2. Ask Claude to run the `health_check` MCP tool. Expect: data dir path, `gitignore` safe,
   no API-key override. If any is unsafe, it tells you exactly what to fix.
3. Prove the scope hook fires — set up a throwaway target and confirm a blocked command:
   - Ask Claude to `create_target "hooktest" "test" "public"` and
     `set_scope_rules "hooktest" [{"pattern":"*.example.com","in_scope":true}]`.
   - Then ask it to run `curl https://not-in-scope.com`. The hook must **deny** it with a
     scope reason. If the command runs, the hook isn't wired — go back to step 3 fallback #3.

---

## 5. Burp Suite MCP (proxy history → ledger)  [you, GUI]  ⚠️

Optional but high-value: it turns your Burp proxy history into mapped endpoints.

1. In **Burp Suite** → Extensions → BApp Store → install **"MCP Server"** (PortSwigger, official).
   ⚠️ It's expected to work on **Community**; if the extension refuses to load or exposes no
   tools, that assumption was wrong and you'll use the file-export fallback below.
2. In the extension's tab, start the server and use its installer button to register with
   Claude Code (or copy the `claude mcp add` command it shows).
3. Restart Claude Code; the `bb-burp` skill will use Burp's **read** tools only.

**Fallback with no Burp MCP:** in Burp, right-click proxy history → Save items → an XML file
in your shared folder, then ask Claude to `ingest_file "<target>" "<path>" "burp"`.

**Where to run Burp:** run it on the **Windows host** so the MCP connects on localhost. Point
your VM's browser at the host's proxy, or run Burp inside the VM and use the file-export path.

---

## 6. VirtualBox shared folder (VM recon output → Windows)  [you, GUI]

Your recon tools (nuclei/ffuf/subfinder/httpx/katana) run in the Linux VM; the MCP server
reads files on Windows. Bridge them with a shared folder.

1. **VM powered off** → VirtualBox → the VM → Settings → Shared Folders → add:
   - Folder Path: a Windows dir, e.g. `C:\Users\Tang Cong Han\bb-share`
   - Name: `bbshare` · check **Auto-mount** and **Make Permanent**.
2. Start the VM. In the guest (Ubuntu/Kali), the folder mounts at `/media/sf_bbshare`
   (add yourself to the `vboxsf` group if you get permission denied: `sudo usermod -aG vboxsf $USER`, then re-login).
3. Run recon in the VM, writing output into `/media/sf_bbshare/`, e.g.
   `nuclei -u https://target -jsonl -o /media/sf_bbshare/nuclei.jsonl`.
4. On Windows, ask Claude to `ingest_file "<target>" "C:\Users\Tang Cong Han\bb-share\nuclei.jsonl"`
   (kind auto-detects).

---

## 7. Anthropic cyber safeguards / CVP  [you, only if needed]  ⚠️

v1 is analysis, organization, and writing — it should not trip exploitation safeguards.
If you ever hit a refusal on something clearly authorized, that's the moment to look at
Anthropic's Cyber Verification Program. Note: it appears to be org-scoped and may not be
available to an individual on a Pro/Max subscription — unverified. Not needed to use v1.

---

## 8. Daily workflow (once set up)

1. `bb-pick` — choose or record the program (desk research only).
2. `bb-scope` — pull/enter scope; confirm the rules before they're set.
3. Browse the target through Burp / run recon in the VM.
4. `bb-recon` / `bb-burp` — ingest what you produced.
5. `bb-next` — get the ranked next action, with the *why*.
6. Test it yourself; record the result (`record_coverage`).
7. `bb-correlate` — bank primitives, chase chains.
8. On a confirmed bug: `bb-report` → `bb-gate` before you submit.
9. `bb-review` — close the session so the next one starts warm.

The assistant proposes; you execute every action that touches a live target.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `bb-*` skills don't appear | Plugin didn't load — use step 3 fallback (copy skills to `~/.claude/skills`). |
| Scope hook never blocks anything | Hook not wired — step 3 fallback #3; confirm with step 4.3. |
| `health_check` says data dir is unsafe | Move `BB_DATA_DIR` out of the git-with-remote repo it names. |
| MCP tools missing in Claude | Server not registered — `claude mcp list`; re-add per step 3 fallback #2. |
| Ingest says everything `skipped_malformed` | Wrong `kind`, or the file isn't the tool output you think — check the file. |
| Claude refuses an exploit-dev request | Expected on v1's boundary; see step 7. Rephrase toward analysis, or it's out of scope for v1. |
