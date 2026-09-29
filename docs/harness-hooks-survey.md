# Agent harness hooks for policy gates: capabilities, gaps, conformance

Date: 2026-09-23. Read-only research; nothing was posted upstream.

Source keys:

- [CC] https://code.claude.com/docs/en/hooks (+ permission-modes.md)
- [CX] https://learn.chatgpt.com/docs/hooks + openai/codex issues
- [GM] https://geminicli.com/docs/hooks/reference/
- [CU] https://cursor.com/docs/agent/hooks
- [CP] https://docs.github.com/en/copilot/reference/hooks-configuration
- [VS] https://code.visualstudio.com/docs/copilot/customization/hooks
- [FD] https://docs.factory.ai/reference/hooks-reference
- [OC] https://opencode.ai/docs/plugins/ + anomalyco/opencode source
- [CL] cline/cline `.clinerules/hooks/README.md` + https://docs.cline.bot/sdk/plugins
- [AM] https://ampcode.com/notes/permissions
- [ZD] https://zed.dev/docs/ai/tool-permissions + zed-industries/zed PR #52729
- [DV] https://docs.devin.ai/cli/extensibility/hooks/overview
- [GK] xai-org/grok-build `crates/codegen/xai-grok-pager/docs/user-guide/10-hooks.md`
- [PI] badlogic/pi-mono `packages/coding-agent/docs/extensions.md`
- [WA] warpdotdev/warp source (HEAD e865a74) and draft PR #15832 (APP-4344)
- [MEM] our earlier survey or live agy test only; not re-verified

Correction to the earlier survey: Grok Build now has allow/ask/deny/defer, `updatedInput`, `updatedToolOutput`, HTTP hooks, managed hooks and folder trust [GK]. "Deny-only" is outdated; "fails open" is still true.

## 1. Capability list (what a policy gate needs from a harness)

### A. Decisions

- **C1 deny + reason.** Pre-action deny. The reason reaches the model as the tool result.
- **C2 ask, reduce-only.** Forces a confirmation even under auto-approve, YOLO, allowlist or a classifier. Never removes a prompt.
- **C3 PermissionRequest allow/deny.** Opt-in. Fires only when the harness would prompt. Never overrides managed deny, protected paths or critical paths ([CC] "actions no mode auto-approves").
- **C4 defer.** "No opinion" is a separate value from allow ([CC], [GK]).
- **C5 input rewrite (optional).** The harness re-validates the rewritten input, shows it in the prompt, and applies every decision to the rewritten input ([GK]).
- **C6 headless semantics.**
  - ask becomes deny, with the reason.
  - allow is honored headless (counterexample: agy #1053 [MEM]).
  - deny is honored in bypass/YOLO modes.
- **C7 scoped remember.** A remembered allow has a scope (once / session / project / user) and a match key. [CC] `updatedPermissions.destination` has the scopes, but no expiry and no exact-input key.

### B. Input

- **C8 full input values, bounded,** with truncation metadata: MCP argument values, file content or diffs, the program a PTY write goes to, child-agent prompts, URLs.
- **C9 tool identity.** Canonical tool name, MCP server name, where the server's config came from ([CC] `mcp_server.source`).
- **C10 stable ids.** `session_id`, turn / `prompt_id`, `tool_use_id`, `agent_id` / `parent_session_id`.
- **C11 user intent.** Latest user prompt, and transcript access including tool outputs. User-typed messages are marked apart from synthetic ones.
- **C12 context.** `cwd`, workspace roots, `permission_mode`, sandbox/network state, harness version, model.
- **C13 harness classification.** The harness's own native permission result as a field, separate from model-proposed risk flags (Warp `is_risky`).

### C. Content and provenance

- **C14 output hook.** Replace, withhold or annotate any tool output before the model reads it.
- **C15 provenance tags.** Mark content from untrusted sources (web, remote MCP, files outside the workspace), and carry the marks into later PreToolUse events.
- **C16 gate-only channel.** A note for the classifier/gate, not the model ([CC] `classifierContext`).

### D. Multiple agents

- **C17 subagents.** Subagent tool calls fire the same hooks with `agent_id` and the parent id. SubagentStart shows the child's prompt.
- **C18 agent-to-agent traffic.** Agent-to-agent messages and agent spawns are tool events with full content.

### E. Hook integrity

- **C19 fail-closed option.** Crash, bad JSON or an unparseable config never becomes a silent run.
- **C20 timeout rule.** A timeout counts as a failure under fail-closed. Copilot timeouts fail open even when other failures deny [CP].
- **C21 tamper protection.** Config is read once at session start. Agent writes to hook config are never auto-approved.
- **C22 precedence.** Managed > user > project. Managed hooks cannot be disabled by the user. `allowManagedHooksOnly`. Signed policy ([GK] signed `requirements.toml`).
- **C23 project trust.** Project hooks run only after trust by exact-byte hash ([CX], APP-4344).
- **C24 environment.** Env allowlist; secrets passed only by name ([CC] `allowedEnvVars`).
- **C25 combining hooks.** Deterministic strictest-wins: deny > ask > allow > defer.

### F. Transport and versioning

- **C26 schema version** in the payload. Unknown input fields are ignored; unsupported output fields are reported.
- **C27 persistent transport.** Long-running stdio JSON-lines, socket or HTTP handler with correlation ids. Measured on this machine (Windows):
  - process spawn: 11-26 ms;
  - Python start + semgate import: 145-218 ms per call;
  - `semgate serve`: about 1 ms per rules-only decision.
- **C28 deadline in the payload.** A `deadline_ms` field, so an LLM-backed hook can return a safe answer instead of being killed.

### G. Audit and UX

- **C29 decision events** for every final outcome: user approved or rejected an ask, a harness rule denied, a hook failed ([CC] PermissionDenied).
- **C30 ask screen.** Shows the hook reason and its source label ([CC] `[settings]`). The user's choice goes back to the hook.
- **C31 sandbox handoff.** The hook can answer "run with network off / in sandbox" instead of deny.
- **C32 parallel calls.** One event per call in a parallel batch, with a defined order ([CC] PostToolBatch).
- **C33 post-tool context.** After a tool ran, the hook can add text the model reads with the result ([CC] `additionalContext`). semgate uses it for the secret exposure notice.
- **C34 message at stop.** When the agent stops, the hook can show text to the user without blocking the stop ([CC] `systemMessage`). semgate uses it for the secret exposure summary.

## 2. Gap matrix

Y = yes, P = partial, N = no, ? = unknown.

| Harness | C1 deny | C2 ask | C3 allow | C8 full values | C11 prompt / transcript | C6 headless | C14 output replace | C17 subagent ids | C19 fail-closed | C22 managed | C23 project trust | C27 transport |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Claude Code [CC] | Y | Y | Y (PermissionRequest + `updatedPermissions`) | Y | Y (`transcript_path`, `prompt_id`) | Y (PermissionRequest with no answer denies headless) | Y (`updatedToolOutput`, all tools) | Y (`agent_id`) | N | Y | P (workspace trust) | command, http, mcp_tool, prompt, agent |
| Codex CLI [CX] | P (#27833: apply_patch deny not enforced) | N (#28437) | Y (PermissionRequest) | P (#20204: uneven coverage) | Y | ? | P (block replaces result; #38135 asks for `updatedToolOutput`) | P (Subagent events; per-tool id not documented) | N | Y | Y (hash) | command, mcp_tool |
| Gemini CLI [GM] | Y | ? ([MEM]: #28046) | ? | Y | Y | ? | Y (AfterTool reason replaces result) | N | N | ? | ? | command; replaced by agy for free users since 2026-06-18 |
| agy 1.2.8 [MEM live] | Y (also YOLO) | Y (interactive) | P (#1053: ignored headless) | Y | Y (`transcriptPath`) | P | ? | ? | ? | ? | N (project hooks not loaded) | command |
| Cursor [CU] | Y | P ("ask… not enforced for preToolUse today") | Y | Y | Y | ? | P (MCP only; `beforeReadFile` can deny) | P (start/stop with `parent_conversation_id`) | Y (`failClosed`) | Y | ? | command |
| Copilot CLI [CP] | Y | Y (cloud: ask becomes deny) | Y (`permissionRequest`) | Y | P (transcript on some events only) | Y | Y (`modifiedResult`) | P | P (timeouts fail open) | Y (policy.d) | ? | command, https |
| VS Code agent [VS] | Y | Y | Y (PreToolUse) | Y | P ("not stable") | n/a | N | P | N | P (org can disable) | ? | command (preview) |
| Factory Droid [FD] | Y | Y | Y (PreToolUse) | Y | Y | ? | N (block adds feedback) | P (SubagentStop, no id) | N | Y | ? | command |
| OpenCode V1 [OC] | Y (throw) | N (#7006; confirmed in source) | N | Y | Y (`client.session.messages`) | ? | ? | ? | Y (throw denies) | N | N | in-process JS (persistent) |
| OpenCode V2 [OC] | Y | N (#47495: ignored) | Y | Y | Y | ? | ? | ? | ? | N | N | in-process; #47356: `cd`-led commands skip the hook |
| Cline [CL] | Y (`cancel`) | N | N | Y | ? | ? | N (`contextModification` only) | ? | P (SDK `failureMode`) | N | N (no Windows support) | command, 30 s |
| Roo / Roomote [MEM] | Roo archived; Roomote runs OpenCode with every permission set to allow | N | N | via OpenCode | via OpenCode | N | ? | ? | N | N | N | OpenCode plugin |
| Amp [AM] | Y (`delegate` exit 2) | Y (exit 1) | Y (exit 0) | Y | N (docs: helper gets no thread) | ? | ? | ? | ? | ? | ? | per-call program |
| Warp today [WA] | N | N | N | N | N | n/a | N | N | N | org denylist only | n/a | none |
| Warp APP-4344 draft (#15832) [WA] | Y | N | N | P (MCP keys only, edit paths only) | P (UserPromptSubmit only) | Y | N | P | Y (`on_failure: deny`) | N | Y | command; has a schema version |
| Zed [ZD] | N (regex `tool_permissions` only) | N | N | - | - | - | - | - | - | - | - | hooks PR #52729 closed 2026-04 ("revisiting after next launch") |
| Devin CLI [DV] | Y (block) | ? | Y (approve; PermissionRequest event exists) | Y | P (`prompt_id`) | ? | N (`additionalContext` only) | ? | N | ? | ? | command; reads `.claude` config |
| Grok Build [GK] | Y | Y | Y (+ defer) | Y (`toolInputTruncated` flag) | P (`promptId`; transcript ?) | ? | Y | P (Subagent events) | N (fail-open by design) | Y (signed) | Y (folder trust) | command, http |
| Pi / oh-my-pi [PI] | Y | P (`ctx.ui.confirm`; no UI in print or JSON mode) | Y | Y | Y (sessionManager) | P | Y (`tool_result`) | N | Y (handler failure blocks the tool) | N | N | in-process TS |

Missing in every harness:

- C15 provenance tags.
- C26 schema version (only APP-4344 has one).
- C28 deadline.
- C31 sandbox handoff.
- C7 expiry and exact-input scope.

## 3. Conformance levels

Each requirement is a black-box test. "Probe" = the recording hook in section 4.

**L0 Observe**

- O1: every documented tool type produces one PreToolUse and one PostToolUse at the probe, with the same `tool_use_id`.
- O2: every event has `session_id`, a turn id, `cwd` and the event name.
- O3: UserPromptSubmit carries the typed prompt byte-for-byte (under the size cap).
- O4: subagent tool calls reach the probe.

**L1 Block**

- B1: deny stops a canary side effect for every tool type (command case: the marker file never appears).
- B2: B1 holds in bypass, YOLO and headless modes.
- B3: the deny reason string appears in the model's next request (measured at the mock model).
- B4: exit 2 with stderr gives the same result as B1-B3.
- B5: with fail-closed set, a hook that crashes, times out or prints garbage stops the canary.
- B6: without fail-closed, a failure shows a visible diagnostic, never a silent success.

**L2 Ask + context**

- A1: ask produces a prompt even with auto-approve on.
- A2: headless ask means the canary is absent and the reason reaches the model.
- A3: MCP argument values, file-edit content and the PTY target program are present at the probe (compared with the injected values).
- A4: the latest prompt, or a readable transcript that includes tool outputs, is present.
- A5: an agent edit of the hook config is refused or prompted, through the edit tool and through the shell.
- A6: a config change mid-session does not remove hooks until the next session.

**L3 Allow + remember**

- P1: PermissionRequest allow runs the canary without a prompt, headless included.
- P2: allow never overrides a managed deny or a protected path.
- P3: a remembered grant covers only its scope and exact input; a changed argument prompts again.
- P4: a decision event records the user's approve or reject choice.
- P5: a managed hook still runs after the user sets disable-all.

**L4 Content + multi-agent**

- M1: output replacement changes what the model receives, for built-in and MCP tools.
- M2: provenance tags mark web, MCP and outside-workspace outputs, and later PreToolUse events list them.
- M3: subagent events carry `agent_id` + parent id; a deny inside a subagent is honored.
- M4: the payload has a schema version, and unknown fields do not break old hooks.
- M5: a persistent-transport handler receives correlated requests, with P95 overhead under 20 ms per call.

## 4. Conformance test kit design

### Parts

1. **Probe.** A small binary (Python is fine for v1). It appends each event to JSONL and answers from scenario rules, e.g. `{match:{tool:"*", event:"PreToolUse"}, respond: deny|ask|allow|crash|sleep|garbage}`.
2. **Mock model server.**
   - Speaks the Anthropic Messages and OpenAI Chat/Responses formats, including streaming tool calls.
   - Sends scripted tool calls, e.g. run `echo HK-B1 > $KIT/marker`.
   - Records every request, which proves B3 and A2 (the reason reached the model).
3. **Per-harness driver.** Writes the hook config and starts the harness headless against the mock base URL. It drives the prompt screen through a PTY (pexpect) for A1 and P1.
4. **Canaries.** Only harmless ones:
   - marker files;
   - a local MCP test server that records its arguments;
   - a local HTTP endpoint.
   
   No destructive commands.
5. **Report.** A JSON + HTML matrix per harness version and level, with the raw events attached.

### Which tests need a real model

**Deterministic, no API key.** Harnesses with a custom model endpoint:

- Claude Code (`ANTHROPIC_BASE_URL`)
- Codex (custom provider)
- OpenCode
- Pi
- Cline
- Grok (probably, per `11-custom-models.md`)
- Droid (BYOK; unverified)

This covers all of L0-L4 except real-model behavior.

**Needs a real model or account.** Cursor, Copilot CLI, VS Code, agy, Warp (the model runs on Warp's server), Devin, Amp. These use natural-language scenarios ("run exactly this command"), repeated N=5 times and scored from the probe records. Results are marked "live".

### Effort estimate

- Probe + scenario schema: 3-4 days.
- Mock model server with streaming tool calls in two formats: 5-7 days.
- Drivers: 1-2 days per headless harness, plus 2-3 days per harness that needs an interactive prompt.
- Report: 2 days.
- **Total for 8 harnesses:** about 5-6 engineer-weeks. After that, each new harness version is a CI re-run.

## 5. Features no harness has yet, ranked by value/effort

### 1. Provenance tags (C15). High value, medium effort.

- **Design.** The harness already knows each output's source.
  - Add `trust: user|workspace|external` to each transcript and PostToolUse entry.
  - Add `untrusted_inputs_since_prompt: [tool_use_id...]` to PreToolUse.
- **What it stops.**
  - GitHub MCP private-repo exfiltration (Invariant Labs, May 2025 - unverified).
  - Antigravity `.env` exfiltration through the browser (PromptArmor, Nov 2025 - unverified).
  - In both, a gate can ask when an outbound action follows untrusted input.
- **Limit.** Taint over-approximates. Use it as a reason to ask, not to deny.

### 2. PermissionRequest grants with exact-input scope and expiry. High value, low effort.

- **Design.** Add `scope: {match: exact_input_hash|prefix, ttl_s, prompt_id}` to Claude's `updatedPermissions` shape.
- **What it stops.** Prefix grants that approve more than the user meant (Tracebit, July 2025: an allowlisted `grep` prefix let `grep ...; curl ...` run in Gemini CLI - unverified).
- semgate's exact-command approval is already this design.

### 3. One cross-harness PermissionRequest schema. Medium value, low effort.

- Claude, Codex, Copilot and Devin already have the event, with different fields.
- Standard fields: `tool_name`, `tool_input`, `suggestions`, `decision{behavior, scope, reason_code}`.

### 4. Sandbox handoff decision (C31). High value, high effort.

- **Design.** `permissionDecision: "allow_sandboxed", network: false`.
- **Where.** Only harnesses that have a sandbox: Claude, Codex, Grok.
- **What it stops.** The Nx "s1ngularity" malware (Aug 2025 - unverified) used AI CLIs with skip-permission flags to collect secrets. A network-off run of an untrusted build script stops the exfiltration without a prompt.

### 5. Standard reason codes + `deadline_ms`. Low effort, medium value.

- **Reason codes:** `credential_access`, `untrusted_instruction`, `not_requested`, `hook_error`.
- **Why.** The UI and the model handle a refusal the same way in every harness, and audits can aggregate. The deadline lets an LLM-backed gate answer ask before it is killed.

### Not ranked

- **Tool-output hooks.** Already in Claude, Copilot, Grok, Gemini and Pi; this is adoption work.
- **Intent/prompt binding.** `prompt_id` already exists in Claude, Devin and Grok; the real gap is C11 (prompt content).
- **Decision cache by input hash.** Low security value. A cached decision is wrong once new untrusted content arrives.

### Adoption item, not new: tamper protection (C21)

Incidents (confirmed by search 2026-09-23):

- **CVE-2025-53773.** A prompt injection made Copilot write `chat.tools.autoApprove: true` into `.vscode/settings.json`.
- **CVE-2025-54135 (CurXecute).** A prompt injection wrote `.cursor/mcp.json`; the new MCP server auto-started and ran code.

## 6. Upstream plan

Upstream proposal drafts are kept outside the repo.

## Open risks

- **Not re-verified.** Rows marked [MEM]: Roomote, parts of agy, Gemini CLI ask.
- **Not checked.**
  - Codex subagent per-tool ids.
  - OpenCode `tool.execute.after` output mutation.
  - Grok transcript access.
- **Incident citations.** Replit, Nx, Tracebit, PromptArmor and Invariant Labs are from memory and marked unverified. Only CVE-2025-53773 and CVE-2025-54135 were confirmed by search.
- **Latency numbers** come from one Windows machine.

## Sources

- Claude Code hooks: https://code.claude.com/docs/en/hooks
- Codex hooks: https://learn.chatgpt.com/docs/hooks
- Gemini CLI hooks: https://geminicli.com/docs/hooks/reference/
- Cursor hooks: https://cursor.com/docs/agent/hooks
- Copilot hooks: https://docs.github.com/en/copilot/reference/hooks-configuration
- VS Code hooks: https://code.visualstudio.com/docs/copilot/customization/hooks
- Factory Droid hooks: https://docs.factory.ai/reference/hooks-reference
- OpenCode plugins: https://opencode.ai/docs/plugins/
- Cline SDK plugins: https://docs.cline.bot/sdk/plugins
- Amp permissions: https://ampcode.com/notes/permissions
- Zed tool permissions: https://zed.dev/docs/ai/tool-permissions
- Devin CLI hooks: https://docs.devin.ai/cli/extensibility/hooks/overview
- Grok Build: https://github.com/xai-org/grok-build
- Pi extensions: https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/extensions.md
- CVE-2025-53773: https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/
- CVE-2025-54135: https://www.tenable.com/cve/CVE-2025-54135
- agent-hook-unity (draft spec): https://github.com/trendmicro/agent-hook-unity
- agenthook (draft spec): https://github.com/agentic-thinking/agenthook
