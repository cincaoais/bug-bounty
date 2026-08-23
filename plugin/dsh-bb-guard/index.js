// Native DeepSeek Harness hook for bb: registers on tools/pre-execute and forwards
// gated tool calls to bb's scope-guard.py (same code Claude Code runs), then maps
// its decision onto the harness PreToolDecision.
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

export const name = 'bb-scope-guard'

const PYTHON = process.env.BB_PYTHON || 'C:/Users/johan/AppData/Local/Programs/Python/Python314/python.exe'
const GUARD = process.env.BB_GUARD_PATH || 'D:/Github/bug-bounty/plugin/hooks/scope-guard.py'
const BB_DATA_DIR = process.env.BB_DATA_DIR || join(homedir(), '.bb-bounty')

// Tool names that can put traffic on the wire in this harness. run_code itself is
// NOT gated: its network always goes through pwsh/bash/web_fetch, which ARE gated.
const GATED = new Set(['pwsh', 'bash', 'web_fetch'])
const GATED_RE = /^mcp__(burp__send_|hexstrike__|claude-in-chrome__)/

function isGated(toolName) {
  return GATED.has(toolName) || GATED_RE.test(toolName)
}

// Run bb's scope-guard.py with a Claude-Code-shaped PreToolUse event. Resolves to
// the raw stdout string, or null when there is nothing decisive (defer).
function runGuard(event) {
  return new Promise((resolve) => {
    let out = ''
    let done = false
    const finish = (value) => { if (!done) { done = true; resolve(value) } }

    let child
    try {
      child = spawn(PYTHON, [GUARD], { stdio: ['pipe', 'pipe', 'ignore'] })
    } catch {
      finish(null) // could not even start the hook -> defer (match bb's "never break the flow")
      return
    }

    const timer = setTimeout(() => { try { child.kill() } catch {} ; finish(null) }, 3000)
    child.stdout.on('data', (d) => { out += d })
    child.stdout.on('end', () => { clearTimeout(timer); finish(out.trim()) })
    child.stdout.on('error', () => { clearTimeout(timer); finish(null) })
    child.on('error', () => { clearTimeout(timer); finish(null) })

    try { child.stdin.write(JSON.stringify(event)) } catch { /* ignore */ }
    try { child.stdin.end() } catch { /* ignore */ }
  })
}

export function apply(ctx) {
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (!isGated(exec.name)) return next()
    // Before bb has ever been initialized there is no state to enforce; skip the spawn.
    if (!existsSync(BB_DATA_DIR)) return next()

    const raw = await runGuard({
      hook_event_name: 'PreToolUse',
      tool_name: exec.name,
      tool_input: exec.arguments ?? {},
      permission_mode: 'default',
    })
    if (!raw) return next()

    let parsed
    try { parsed = JSON.parse(raw) } catch { return next() }
    const out = parsed && parsed.hookSpecificOutput
    if (!out || typeof out !== 'object') return next()

    if (out.permissionDecision === 'deny') {
      return { kind: 'deny', reason: out.permissionDecisionReason || 'Blocked by bb scope-guard' }
    }
    if (out.permissionDecision === 'ask') {
      return { kind: 'ask', reason: out.permissionDecisionReason || 'bb scope-guard requires approval' }
    }
    // 'allow' or additionalContext-only -> defer to normal flow
    return next()
  })
}
