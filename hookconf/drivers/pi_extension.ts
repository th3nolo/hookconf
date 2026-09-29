// hookconf probe bridge for Pi extensions (in-process). Plain JavaScript in a .ts file
// (Pi loads extensions with jiti). Every hook call becomes one probe event; the
// Python probe records it and returns {action, reason, seconds}; this file enacts it:
//   deny          -> tool_call returns { block: true, reason }
//   exit2         -> tool_call throws Error(reason)   (in-process analog of exit 2 + stderr)
//   crash         -> tool_call throws TypeError        (an unexpected extension bug)
//   hang          -> await a sleep of `seconds`, then no opinion
//   ask           -> await ctx.ui.confirm(...); block with the reason unless it returns true
//   replace       -> tool_result returns { content: [{ type: "text", text: reason }] }
//   none / allow / defer / garbage -> no change
// HOOKCONF_TAMPER_EDIT=no HOOKCONF_TAMPER_SHELL=no

import { spawnSync } from "node:child_process"
import { writeFileSync } from "node:fs"
import { join } from "node:path"

const ENABLED = __HOOKCONF_ENABLED__
const PY = "__HOOKCONF_PYTHON__"
const PROBE = "__HOOKCONF_PROBE__"
const LOG = "__HOOKCONF_LOG__"
const SCENARIO = "__HOOKCONF_SCENARIO__"
const TMP = "__HOOKCONF_TMP__"

function probe(event, payload) {
  const res = spawnSync(PY, [PROBE, "--event", event, "--log", LOG, "--scenario", SCENARIO, "--format", "plugin"],
    { input: JSON.stringify(Object.assign({ hook_event_name: event }, payload)), encoding: "utf-8", timeout: 60000 })
  try { return JSON.parse(res.stdout) } catch { return { action: "none", reason: "" } }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function sessionFacts(ctx, callID) {
  // ids and a transcript file, all read from Pi's own session manager
  const sm = ctx.sessionManager
  const out = { session_id: undefined, prompt_entry_id: undefined, transcript_path: undefined, session_file: undefined }
  try { out.session_id = sm.getSessionId() } catch {}
  try { out.session_file = sm.getSessionFile() } catch {}
  try {
    const branch = sm.getBranch() || []
    const users = branch.filter((e) => e && e.type === "message" && e.message && e.message.role === "user")
    if (users.length) out.prompt_entry_id = users[users.length - 1].id
    const p = join(TMP, `hookconf-transcript-${callID || Date.now()}.json`)
    writeFileSync(p, JSON.stringify(sm.getEntries()))
    out.transcript_path = p
  } catch {}
  return out
}

function textOf(content) {
  return (content || []).filter((c) => c && c.type === "text").map((c) => c.text).join("\n")
}

export default function (pi) {
  if (!ENABLED) return
  probe("PluginLoaded", { variant: "pi-extension" })

  pi.on("before_agent_start", async (event, ctx) => {
    const f = sessionFacts(ctx, "prompt")
    probe("UserPromptSubmit", Object.assign(f, { prompt: event.prompt, cwd: ctx.cwd, native_event: "before_agent_start",
      mode: ctx.mode, has_ui: ctx.hasUI }))
  })

  pi.on("tool_call", async (event, ctx) => {
    const f = sessionFacts(ctx, event.toolCallId)
    const r = probe("PreToolUse", Object.assign(f, { tool_name: event.toolName, tool_input: event.input,
      tool_use_id: event.toolCallId, cwd: ctx.cwd, native_event: "tool_call" }))
    if (r.action === "deny") return { block: true, reason: r.reason }
    if (r.action === "exit2") throw new Error(r.reason)
    if (r.action === "crash") throw new TypeError("hookconf probe extension: deliberate crash")
    if (r.action === "hang") {
      await sleep(r.seconds * 1000)
      probe("HangEnd", { for_event: "PreToolUse", tool_use_id: event.toolCallId })
    }
    if (r.action === "ask") {
      let ok
      try { ok = await ctx.ui.confirm("hookconf", r.reason) } catch (err) { ok = `threw: ${err && err.message}` }
      probe("AskOutcome", { tool_use_id: event.toolCallId, confirm_result: ok === undefined ? "undefined" : ok, has_ui: ctx.hasUI })
      if (ok !== true) return { block: true, reason: r.reason }
    }
    return undefined
  })

  pi.on("tool_result", async (event, ctx) => {
    const f = sessionFacts(ctx, event.toolCallId + "-post")
    const r = probe("PostToolUse", Object.assign(f, { tool_name: event.toolName, tool_input: event.input,
      tool_use_id: event.toolCallId, cwd: ctx.cwd, tool_response: textOf(event.content), is_error: event.isError,
      native_event: "tool_result" }))
    if (r.action === "replace") return { content: [{ type: "text", text: r.reason }] }
    return undefined
  })
}
