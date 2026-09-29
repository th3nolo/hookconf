// hookconf probe bridge for OpenCode plugins (in-process). Standard Node/Bun APIs only.
//
// Every hook call becomes one probe event: the Python probe records it and
// returns {action, reason, seconds}; this file enacts the action the way an
// in-process plugin can:
//   deny / exit2  -> throw Error(reason)          (OpenCode: a throw blocks the tool)
//   crash         -> throw TypeError (an unexpected plugin bug)
//   hang          -> await a sleep of `seconds`, then no opinion
//   replace       -> PostToolUse: output.output = reason
//   perm_allow / perm_deny -> permission.ask: output.status = allow / deny
//   ask / allow / none / defer / garbage -> no change (V1 has no ask value)
//
// HOOKCONF_VARIANT selects the exported API: "v1" exports server() (hooks
// object), "v2" exports setup(ctx) (ctx.tool.hook). The kit writes one file
// per run, so a run measures exactly one API.
// HOOKCONF_TAMPER_EDIT=no HOOKCONF_TAMPER_SHELL=no

import { spawnSync } from "node:child_process"
import { writeFileSync } from "node:fs"
import { join } from "node:path"

const VARIANT = "__HOOKCONF_VARIANT__"
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

async function enactPre(r, toolUseID) {
  if (r.action === "deny" || r.action === "exit2") throw new Error(r.reason)
  if (r.action === "crash") throw new TypeError("hookconf probe plugin: deliberate crash")
  if (r.action === "hang") {
    await sleep(r.seconds * 1000)
    probe("HangEnd", { for_event: "PreToolUse", tool_use_id: toolUseID })
  }
}

function textOf(parts) {
  return (parts || []).filter((p) => p && p.type === "text" && !p.synthetic).map((p) => p.text).join("\n")
}

const argsByCall = new Map()

async function transcriptPath(client, sessionID, callID) {
  // A4: what a V1 hook can read about the session so far (client.session.messages)
  try {
    const res = await client.session.messages({ path: { id: sessionID } })
    const list = Array.isArray(res) ? res : (res && res.data) || []
    const p = join(TMP, `hookconf-transcript-${callID || Date.now()}.json`)
    writeFileSync(p, JSON.stringify(list))
    return p
  } catch (err) {
    return undefined
  }
}

const v1 = {
  id: "hookconf-probe",
  async server({ client, directory }) {
    probe("PluginLoaded", { variant: "v1", api: "server", cwd: directory })
    return {
      "chat.message": async (input, output) => {
        probe("UserPromptSubmit", { session_id: input.sessionID,
          prompt_message_id: input.messageID || (output && output.message && output.message.id),
          prompt: textOf(output && output.parts), cwd: directory, native_event: "chat.message", native_input: input })
      },
      "tool.execute.before": async (input, output) => {
        argsByCall.set(input.callID, output.args)
        const tp = await transcriptPath(client, input.sessionID, input.callID)
        await enactPre(probe("PreToolUse", { session_id: input.sessionID, tool_name: input.tool, tool_input: output.args,
          tool_use_id: input.callID, cwd: directory, transcript_path: tp, native_event: "tool.execute.before",
          native_input: input }), input.callID)
      },
      "tool.execute.after": async (input, output) => {
        const r = probe("PostToolUse", { session_id: input.sessionID, tool_name: input.tool,
          tool_input: input.args || argsByCall.get(input.callID), tool_use_id: input.callID, cwd: directory,
          tool_response: output && output.output, native_event: "tool.execute.after", native_input: input })
        if (r.action === "replace" && output) output.output = r.reason
      },
      "permission.ask": async (input, output) => {
        const r = probe("PermissionRequest", { session_id: input.sessionID, tool_name: input.type || input.permission,
          tool_input: input.metadata || input.pattern || input.patterns, tool_use_id: input.callID, cwd: directory,
          native_event: "permission.ask", native_input: input })
        if (r.action === "perm_allow") output.status = "allow"
        if (r.action === "perm_deny") output.status = "deny"
      },
    }
  },
}

const v2 = {
  id: "hookconf-probe",
  async setup(ctx) {
    probe("PluginLoaded", { variant: "v2", api: "setup", ctx_keys: Object.keys(ctx || {}) })
    await ctx.tool.hook("execute.before", async (event) => {
      await enactPre(probe("PreToolUse", { session_id: event.sessionID, tool_name: event.tool, tool_input: event.input,
        tool_use_id: event.id, cwd: process.cwd(), native_event: "execute.before", native_input: event }), event.id)
    })
  },
}

export default ENABLED ? (VARIANT === "v2" ? v2 : v1) : { id: "hookconf-probe" }
