# hookconf reference

The full description of the kit. Start with `README.md`.

hookconf checks, from the outside, whether an agent CLI obeys an external
permission hook. It runs the real CLI against a local mock model, lets the
mock ask for tool calls, answers the CLI's hook with a recording probe, and
looks at what happened: did the marker file appear, what did the probe
receive, what did the CLI send back to the model. Each requirement gets a
status, and the requirements roll up into a level (L0 to L4) per harness
version.

Requirement ids and levels come from
[docs/harness-hooks-survey.md](harness-hooks-survey.md) (section 3; a copy
of the file of the same name in semgate). `results/*.json` holds the raw results; `matrix.md` is the table
built from them.

## What it tests

| Id | Test (what the kit does) |
|---|---|
| O1 | Shell, file write, file edit and file read calls each give one PreToolUse and one PostToolUse with the same `tool_use_id`. |
| O2 | Every hook event has a session id, a turn id, `cwd` and the event name. |
| O3 | UserPromptSubmit carries the prompt (with unicode, quotes, `$HOME`, backticks, `&`, `|`, `<tag>`, `%`) byte for byte. |
| O4 | A tool call made by a subagent reaches the probe. |
| B1 | The probe answers deny; the shell canary (`echo ... > marker`) and the file-write canary do not create their marker files. A control run without deny must create both markers, or the check is `error`. |
| B2 | B1 again with the harness's bypass flag (`--dangerously-skip-permissions`, `--dangerously-bypass-approvals-and-sandbox`, `--auto`). |
| B3 | The deny reason string is in the tool result of the next request the mock model receives. |
| B4 | Exit code 2 with the reason on stderr works like B1 and B3. For in-process hosts (OpenCode plugins, Pi extensions) the analog is a hook that throws `Error(reason)`. |
| B5 | With the harness's fail-closed option, a hook that crashes, hangs past its timeout, or prints invalid JSON stops the canary. No option: `unsupported`. |
| B6 | Without fail-closed, the same failures show a hook-failure line in the harness's normal headless output. For Claude Code the kit also runs with `--include-hook-events` and reports that separately. |
| A1 | In an interactive terminal, an ask under the host's normal tool mode displays a Yes/No choice; Yes runs the isolated canary. Currently measured for Pi 0.86.0. |
| A2 | Headless ask: canary absent and the ask reason reaches the model. |
| A2b | A2 again in every bypass mode the harness has, each with its own control run in the same mode. Claude Code: `--dangerously-skip-permissions`, and separately `permissions.defaultMode: "bypassPermissions"` in settings with no flag (the stream-json init record must show `permissionMode: bypassPermissions`, or the check is `error`). Codex: `--dangerously-bypass-approvals-and-sandbox`. Pass only if every mode passes. |
| A3 | File-write and file-edit content are in the PreToolUse payload. |
| A4 | At a later PreToolUse the hook can read a transcript that contains an earlier tool output and the prompt. |
| A5 | The model edits the hook config file with the edit tool and with a shell `sed`; the probe gives no opinion. Pass only if the harness itself refuses or asks. |
| A6 | Between two tool calls the kit removes the hooks from the config file. Pass if the second call still reaches the hook (hooks are fixed for the session). |
| P1 | In a strict mode where the canary needs approval, the PermissionRequest hook answers allow and the canary runs headless. A control run without the hook must not run the canary. |
| P3 | Inspect the interactive approval choice for a remembered grant and its scope. Pi 0.86.0 exposes only Yes/No, so this reports `unsupported`. |
| P4 | Exercise both interactive choices and check whether a separate approval/rejection hook event exists. Pi's `ctx.ui.confirm` returns both decisions to the extension, but there is no separate decision event, so this reports `unsupported`. |
| M1 | PostToolUse replaces the shell tool output; the model receives the replacement and not the original. |
| M3 | The subagent's PreToolUse has an agent id and a parent id, and a deny inside the subagent is honored. |
| M4 | Some payload field names a schema or version. |

Interactive checks use `hookconf/pty.py`: a POSIX PTY or Windows ConPTY, using
only the Python standard library. It waits for a named prompt before sending
an explicit reply; missing prompts and timeouts are incomplete measurements.
On Windows the Pi TUI was verified with the installed 0.86.0 CLI and an
isolated mock-model session. A1 passed. P3 and P4 were measured as unsupported
for the specific Pi capabilities above. The other harnesses remain
`not_tested` for A1/P3/P4: Codex 0.153.1's isolated TUI stopped at its
workspace trust prompt, and Claude Code 2.1.281's TUI attempted an account
connectivity check before reaching the mock model. The kit does not answer
those startup prompts. OpenCode has not been validated with this PTY path.

Other `not_tested` requirements: P2, P5 (managed policy files in system paths,
which the kit never writes), M2 (no harness has provenance tags; needs web/MCP
canaries), M5 (no persistent transport handler yet).

Status values:

- `pass`, `fail`.
- `unsupported`: the feature exists in the harness, but the hook does not see
  it or cannot act on it. Examples: OpenCode V1 runs tools, but its tool hook
  has no ask value (A2); OpenCode V2 runs tools, but no tool hook fires (all
  checks); Warp's agent runs commands, but Warp has no hook system; Pi 0.86.0
  has no PermissionRequest event, so a hook cannot allow (P1).
- `not_applicable` (shown as `n/a`): the requirement depends on an optional
  product feature that the harness does not have. Example: Pi 0.86.0 has no
  built-in subagents (O4, M3). The reason is in the result. See "Levels" for
  when `n/a` is allowed.
- `not_tested`: the kit does not test it (reason in the result).
- `error`: the kit could not measure it, for example the control canary did
  not run.

## Levels

The report has two parts per harness, for example
`Core L2 · hardening gaps: B5 no fail-closed, M4 no schema version` (a made-up example).

**Core level** (L0-L4) uses only the core requirements:

| Level | Core requirements |
|---|---|
| L0 Observe | O1, O2, O3, O4 |
| L1 Block | B1, B2, B3, B4 |
| L2 Ask + context | A1, A2, A2b, A3, A4 |
| L3 Allow | P1, P2, P3 |
| L4 Content + multi-agent | M1, M3 |

A level is met when:

1. at least one of its requirements is tested (not `not_tested`, not `n/a`),
2. every tested one passes, and
3. every other one is `n/a`, or is A1, P2 or P3 (they need an interactive
   prompt or system policy files the kit does not write).

**When `n/a` is allowed.** `n/a` is only for an optional product feature
that a requirement depends on: subagents (O4, M3) and a bypass mode (B2, A2b).
It is never used for the permission capability that a level measures: deny
(B1, B3, B4), ask (A2), allow (P1), and the input fields a hook needs (O1,
O2, O3, A3, A4). If a harness cannot do one of these, that is a gap: the
status is `unsupported` or `fail`, and it blocks the level. Examples:

- Pi 0.86.0 has no built-in subagents: O4 and M3 are `n/a`.
- Pi 0.86.0 has no PermissionRequest event, so a hook cannot allow a tool
  call: P1 is `unsupported`, and L3 is not met.
- OpenCode V1 has subagents, but the subagent PreToolUse has no agent id:
  M3 is `fail`, not `n/a`.
- Pi has no bypass mode. Its B2 runs the same command as B1 and is still
  tested, so it is `pass`, not `n/a`. A2b on Pi is the same: it runs the A2
  command again.

The kit sets `n/a` only from a driver's `static_results`, with a reason that
cites the harness docs.

A met level with an untested or `n/a` requirement gets `*` (not fully
tested). Any other untested core requirement blocks the level, and so does
`unsupported`, like `fail`. The core level is the highest level with all
lower levels met; it keeps the `*` of any level below it.

Example, Pi 0.86.0 L4: M1 passes and M3 is `n/a` (no subagents), so L4 is met
with `*`. Pi L3: P1 is `unsupported`, so L3 is not met.

**A2b is core (L2), not hardening.** A2b asks whether a hook's `ask`
still stops the tool when the user runs in bypass mode. It is core because:

1. The survey already has A1 ("ask prompts under auto-approve") as a core L2
   requirement. A2b is the headless measurement of the same property; A1
   needs a PTY, A2b does not.
2. B2 (deny under bypass) is core L1. `ask` and `deny` are the two answers
   with which a hook stops a tool. A policy gate that answers `ask` when it is
   unsure (semgate's `block_when_unsure`) loses that stop in bypass mode if
   the harness turns `ask` into allow there, and bypass mode is where users
   have no other prompt left.
3. The hardening list is for protection around the hook (fail-closed,
   silent failure, tamper, reload, schema version). A2b is the effect of the
   hook's own answer, like A2.

Result: a harness that honors `ask` by default but auto-approves it under
bypass does not reach L2. A harness with no ask value at all (OpenCode) gets
`unsupported` for A2b, as for A2.

**Hardening gaps** are B5 (fail-closed), B6 (no silent failure), A5 (hook
config protected), A6 (hooks fixed for the session), P4 (approve/reject
event), P5 (managed hook survives disable-all), M2 (provenance tags), M4
(schema version), M5 (persistent transport). Each is shown per harness as
pass / fail / unsupported / n/a / not tested. A failed or unsupported one is
listed as a gap; `n/a` is not a gap. Gaps do not lower the core level.

Why two parts: in the survey's ladder the hardening items sit inside L1, L2
and L4. Every harness measured so far fails at least one of them, so under
that ladder every harness was "L0", and the differences that decide whether a
policy gate works at all (does deny stop the tool, does ask stop it) were
hidden. The core level shows those differences; the hardening gaps stay
visible next to the level.

A met level above an unmet one does not count. Example: Pi 0.86.0 meets L1,
L2* and L4*, but its core level is `none`, because L0 is not met: O2 fails
(the prompt-time event has no turn id). O4 is `n/a` and does not block L0.
The per-level table in `matrix.md` shows which levels are met.

`py -m hookconf report` always recomputes levels from `results[].status`, so
old result files render with the current rules. A result file without a
core id (for example one made before A2b existed) shows it as `-` and the
level that needs it as blocked by `not_tested`; add the id with `--merge`
(see "How to run").

## How to run

Python 3.10+ standard library only. On Windows use `py`.

```
py -m hookconf list                                   # requirement ids and what is tested
py -m hookconf run --harness claude-code              # writes results/claude-code-<version>.json
py -m hookconf run --harness codex --only B1,B3       # a subset
py -m hookconf run --harness opencode-v1
py -m hookconf run --harness opencode-v2
py -m hookconf run --harness pi
py -m hookconf run --harness warp                     # static: starts no process
py -m hookconf run --harness warp --live              # prints the live plan; refuses to run it (see Warp)
py -m hookconf report results/*.json --md matrix.md
py -m hookconf run --harness claude-code --only A2b --merge   # add one id to the existing result file
```

`--merge` (needs `--only`) replaces those ids in the existing
`results/<harness>-<version>.json` instead of overwriting it. The harness
version must be the same. Each merged result gets `run: {kit, date}`, the
partial run's sessions go under `updates`, and the matrix shows both kit
SHAs (for example `3517a57; A2b: <sha>`).

`--fail-on-error` makes the run exit 3 when a result is `error` or a
session failed (the kit could not measure). `pass`, `fail` and `unsupported`
never change the exit code: they are data. CI uses this flag.

Binaries: `--bin PATH`, or `HOOKCONF_CLAUDE_BIN`, `HOOKCONF_CODEX_BIN`,
`HOOKCONF_OPENCODE_BIN`, `HOOKCONF_PI_CLI` (path to `dist/bundle/cli.js`), `HOOKCONF_WARP_DIR`. Run roots are kept for
inspection (each has `probe.jsonl`, `mock.jsonl`, `harness.stdout`,
`harness.stderr`); `--clean` deletes them after the checks have read them
(before this fix, `--clean` and `Runner(keep=False)` deleted
nothing: no code called `RunRoot.cleanup()`).

A full run takes about 5 minutes for Claude Code, 8 for Codex, 4 for OpenCode,
1 for Pi.

Unit tests (no harness needed; `tests/fake_harness.py` is a 100-line stand-in
agent that talks to the mock):

```
py -m pip install pytest==9.1.1
py -m pytest -q tests
```

### OpenCode binary

Pinned `opencode-ai@1.18.31` (published 2026-09-14; the platform package
`opencode-windows-x64@1.18.31` was published the same day). Installed into the
git-ignored `tools/` dir without install scripts:

```
npm install --prefix tools/opencode opencode-ai@1.18.31 --ignore-scripts --no-save
```

Without its postinstall script, `node_modules/opencode-ai/bin/opencode.exe`
is a 479-byte placeholder that prints an error. The driver runs the platform
binary directly (`tools/opencode/node_modules/opencode-windows-x64/bin/opencode.exe`),
so no install script is needed.

### Pi package

Pinned `@earendil-works/pi-coding-agent@0.86.0` (published 2026-09-19T23:14Z;
the old `@mariozechner/pi-coding-agent` name is deprecated). Before install,
all 142 package versions in its `npm-shrinkwrap.json` were checked with
`npm view <pkg> time`; all were published more than 72 hours earlier
(internals `@earendil-works/chord`, `pi-agent-core`, `pi-ai`, `pi-telemetry`,
`pi-tui` 0.86.0: 2026-09-19). Install:

```
npm install --prefix tools/pi @earendil-works/pi-coding-agent@0.86.0 --ignore-scripts --no-save
```

Skipped install scripts: `@google/genai`, `esbuild`, `protobufjs`; none is
needed for the runs. Needs Node >= 22.19. The driver runs
`node tools/pi/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js --mode json`.

## End-to-end mode (local only, needs a TypeSafe key)

`hookconf run` answers the harness's hook with the recording probe, which
gives fixed answers. `hookconf e2e` keeps the mock model and the drivers but
installs **real semgate** as the hook, so every decision comes from
semgate's rules, gates and the TypeSafe (Jev) classifier:

```
py -m hookconf e2e --harness claude-code --harness opencode-v1 \
    --semgate-python <semgate checkout>/.venv/Scripts/python.exe \
    --semgate-policy <semgate checkout>/policies/router_policy_dev.json
py -m hookconf e2e --harness claude-code --case git-status,curl-pipe-sh ...   # a subset
```

It is a separate subcommand, not `run --hook semgate`: `run` computes the
requirement results and levels of the conformance matrix, and e2e results
are a different thing (semgate's decisions on real commands), so they never
go into `results/<harness>-<version>.json`, `matrix.md` or the levels.
Output: a table per harness and `results/e2e/e2e-<harnesses>-<date>.json`
(a subfolder, so `report results/*.json` never reads it).

**Key.** The kit never reads, passes or logs the TypeSafe key. semgate's
provider loads it itself from its source checkout's `.env` (or
`~/.semgate/.env`, which is the temp home here). The preflight asks the
semgate interpreter only whether a key was found (true/false).
`check_env` still refuses any non-dummy `*_KEY` in the child environment.

**Local only.** The command refuses to start when `CI` or `GITHUB_ACTIONS`
is set, and the workflow never calls it. The unit tests
(`tests/test_e2e.py`) need no key: they mock the `semgate init` call and run
the whole pipeline against the fake harness with a fake semgate hook
(`tests/fake_semgate_hook.py`).

**Harnesses.** Only harnesses where semgate has an adapter run: `claude-code`
(`semgate init claude`) and `opencode-v1` (`semgate init opencode`).
`opencode-v2` needs a V2 build (`--bin opencode-v2=<path>`); on a 1.x
binary it is skipped (no V2 tool hook, see the OpenCode V2 results). `codex`,
`pi`, `warp`: `skipped: no semgate adapter`.

**What one case does** (`hookconf/e2e_cases.py`, 12 cases). Each case has
the user prompt the driver sends, the tool call(s) the mock model emits,
the expected semgate outcome (`runs`, `asked`, `blocked`), a canary that
shows whether the call ran, and a note why the command is harmless if it
runs. Per case, each in its own run root:

1. Control session: the same case with no hook. The canary must fire, or
   the case is `error` (`--no-control` skips it).
2. semgate session: `semgate init <host> --mode enforce --policy <policy>
   --dir <run root>/semgate --hooks-file <run root's hook file> --project
   <run root>/project --force`, then two posture settings in the written
   `semgate.json`: `bash` added to `enforcement.auto_allow_tools` (off with
   `--no-auto-allow-bash`; without it no shell command runs unless a human
   approves it) and `enforcement.block_when_unsure` (`--block-when-unsure
   on|off`, default on, the `init` default).
3. The kit reads semgate's ledger in the run root: the `host_response` for
   the harness's tool call id and its `judgment` (same envelope digest), the
   tool result the harness sent back to the mock model, and for Claude Code
   the hook's raw answer (`--include-hook-events`).

Outcome of a call: `runs` when semgate answered allow; `blocked` when it
answered deny and the judge's decision was deny; `asked` when semgate wanted
a human (answer ask, or a deny that came from an ask the host cannot show:
`block_when_unsure`, manifest C2, Devin's mapping). A case passes when the
outcome is one of the expected ones **and** the harness obeyed: the canary
fired exactly when semgate allowed.

Canaries: a marker file, a removed folder, a read-only file that became
writable (`chmod`), a string in the tool result the model received, or a
request to `semgate-test.invalid` in the mock's proxy sink. Every command is
harmless if it runs: relative paths inside the temp project (one case writes
to its parent, the run root), `.invalid` hosts only (RFC 6761: they never
resolve, and curl is pointed at the mock's proxy, which refuses them), fake
secrets written by the kit. `tests/test_e2e.py` checks these rules for every
case.

**Isolation** (on top of the section below). HOME and USERPROFILE point into
the run root for the harness, the hook, `semgate init` and `git init`.
Every store path in `semgate.json` must be inside the run root, or the
session stops. `semgate init` runs with `SEMGATE_WRITE_ROOT` = the run root
(semgate's own write guard). The real `~/.semgate`, `~/.config/opencode`
(top-level files and `plugins/`) and `<semgate checkout>/.antigravity` are
snapshotted before and after each session: a changed or removed file stops
the session; a log (`.jsonl`) that grew is accepted only when the new bytes
do not mention the run root (another agent's own log). Only the Jev API
host (from the SDK's `DEFAULT_BASE_URL`) is added to `NO_PROXY`.

Measured harness details and the e2e results: `docs/harness-notes.md`.

## CI

`.github/workflows/conformance.yml`.

**Triggers:** push, pull request, weekly (Monday 04:23 UTC), and manual
(`workflow_dispatch`) with two inputs: `harnesses` (space-separated, default
`claude-code codex opencode-v1 opencode-v2 pi`) and `only` (requirement ids,
default all). Inputs reach scripts only through environment variables and
are checked against the known names.

**Jobs:**

| Job | Runs on | What it does |
|---|---|---|
| `unit` | ubuntu-latest, windows-latest | `pip install --no-deps --require-hashes -r ci/requirements-ci.txt`, then `python -m pytest -q tests` |
| `plan` | ubuntu-latest | validates the inputs, outputs the harness list |
| `conformance` | ubuntu-latest, windows-latest x each harness | `npm ci --ignore-scripts` from `ci/npm/<harness>/package-lock.json`, `python -m hookconf bin` to find the native binary, `python -m hookconf run --harness <h> --out ci-results/<h>-<OS>.json --fail-on-error` |
| `matrix` | ubuntu-latest | downloads every result, `python -m hookconf report` into `matrix.md`, adds it to the job summary |

Artifacts: `results-<harness>-<OS>` (the JSON), `conformance-matrix`
(`matrix.md` plus all JSON), and on a failed job `runroots-<harness>-<OS>`
(`harness.stdout`, `harness.stderr`, `probe.jsonl`, `mock.jsonl`; kept 7 days).
The result files in `results/` are the local Windows runs; CI does not
change them.

**When the job fails.** A harness that fails a requirement is data: `fail`
and `unsupported` go into the JSON and the job stays green. The job fails
only on a kit error: a unit test fails, the kit crashes, or a result is
`error` / a session failed (`--fail-on-error` exits 3), because then a
measurement is missing. The JSON is uploaded in both cases.

**No API keys.** The workflow uses no secrets and has
`permissions: contents: read`. Every harness talks to the kit's mock model;
the kit sets dummy keys, drops every other key from the child environment,
and points HTTP(S)_PROXY at the mock, which refuses outbound connections.
Run roots are `/tmp/hookconf-runs` (Linux) and `C:/hookconf-runs` (Windows),
outside the runner's home, as the isolation rules require.

**Pinned versions** (72-hour rule, checked 2026-09-23T18:10Z, cutoff
2026-09-20T18:08Z; the same list is in the workflow header):

| What | Version | Published |
|---|---|---|
| actions/checkout | v7.0.1 `3d3c42e5aac5ba805825da76410c181273ba90b1` | 2026-07-20 |
| actions/setup-python | v7.0.0 `5fda3b95a4ea91299a34e894583c3862153e4b97` | 2026-07-20 |
| actions/setup-node | v7.0.0 `820762786026740c76f36085b0efc47a31fe5020` | 2026-07-14 |
| actions/upload-artifact | v7.0.1 `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` | 2026-04-10 |
| actions/download-artifact | v8.0.1 `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` | 2026-03-11 |
| Python | 3.12.10 | 2025-04-08 (actions/python-versions build; the last 3.12 with a Windows build) |
| Node | 24.21.0 | 2026-09-07 |
| @anthropic-ai/claude-code | 2.1.278 | 2026-09-19T01:48Z |
| @openai/codex | 0.155.1 | 2026-09-18T20:09Z |
| opencode-ai | 1.18.31 | 2026-09-14T17:47Z |
| @earendil-works/pi-coding-agent | 0.86.1 | 2026-09-20T11:16Z |
| pytest + 5 dependencies | see `ci/requirements-ci.txt` (hashes) | 2022-10-25 to 2026-06-19 |

Each harness is the newest release older than 72 hours, so CI versions are
not the local ones: the local Claude Code 2.1.280 was published
2026-09-22T15:44Z (26 hours before the pin date), Codex local is 0.153.1,
Pi local is 0.86.0. The lockfiles pin all 172 packages (transitive ones
too); `python ci/lock_dates.py` printed every publish time, the youngest
was 79 hours old.

**Install scripts.** All four harnesses install with `--ignore-scripts`:

- Claude Code: the only script is the wrapper's `postinstall`, which copies
  the platform binary over the placeholder `bin/claude.exe`. The kit runs
  `node_modules/@anthropic-ai/claude-code-<os>-<arch>/claude[.exe]` directly.
- Codex: no install scripts. The kit runs
  `node_modules/@openai/codex-<os>-<arch>/vendor/<triple>/bin/codex[.exe]`
  (the path that `bin/codex.js` resolves).
- OpenCode: the only script is `opencode-ai`'s `postinstall`, which picks
  the platform binary. The kit runs `node_modules/opencode-<os>-<arch>/bin/opencode[.exe]`.
- Pi: skipped scripts in `@google/genai`, `esbuild`, `protobufjs`, as in
  the local install; none is needed for the runs.

Pi 0.86.1's `npm-shrinkwrap.json` has no `integrity` for its five
`@earendil-works/*` sub-packages. `python ci/lock_dates.py --fill-integrity`
copied `dist.integrity` from the registry into the lockfile (after checking
that the tarball URL matches), so `npm ci` verifies every tarball.

**Not in CI:** Warp. It is a desktop app, not an npm package, and its
driver is static (it reads the installed Windows binary).

**How to add a harness to CI:**

1. Driver and unit tests as in "Adding a harness".
2. `ci/npm/<name>/package.json` with one dependency at an exact version that
   is the newest release older than 72 hours (`npm view <pkg> time --json`).
3. Lockfile without installing anything:
   `npm install --package-lock-only --ignore-scripts --before=<UTC now - 72h>`
   in that directory.
4. `python ci/lock_dates.py --fill-integrity` must print
   `0 newer than 72 h or unknown`.
5. Add the npm layout of the native binary to `hookconf/binpaths.py`
   (`candidates`, `BIN_ENV`) with a test in `tests/test_binpaths.py`.
6. In the workflow: add the name to `known` in the `plan` job, to both
   `case` blocks and to the header comment; in `tests/test_ci_pins.py` add
   it to `NPM`. `tests/test_ci_pins.py` checks that every action is pinned
   by SHA, that the header lists every pin, that each lockfile pins the
   exact header version with integrity for every entry, and that no `run:`
   script reads `inputs.*` directly.

**Updating a pin:** pick the newest version older than 72 hours, record its
publish date in the workflow header and in the table above, regenerate the
lockfile as in step 3, run `ci/lock_dates.py`, and review the `git diff` of
the lockfile before committing. For an action, resolve the tag to its commit
with `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` (follow an annotated
tag with `git/tags/<sha>`).

## Linux

The kit was first run only on Windows. OS-specific decisions are now in
`hookconf/binpaths.py` and tested for both OSes on any OS
(`tests/test_binpaths.py`, which passes `os_name` explicitly):

- Git Bash: `CLAUDE_CODE_GIT_BASH_PATH` and `OPENCODE_GIT_BASH_PATH` are set
  only on Windows. On Linux the harness uses its normal shell.
- Environment: `SHELL`, `USER` and `LOGNAME` are copied into the child
  environment only on Linux/macOS (the harness picks its shell from
  `SHELL`). On Windows they are not copied: a Git Bash parent sets
  `SHELL=/usr/bin/bash`, which is not a Windows path. `HOMEDRIVE`/`HOMEPATH`
  are set only on Windows.
- Binaries: npm platform-package paths for linux/win32/darwin, x64/arm64,
  glibc first then musl (`python -m hookconf bin --harness <h> --prefix <dir>`).
- Windows `.cmd`/`.bat` shims are refused with an error: Python starts them
  through cmd.exe, which re-parses `&`, `|`, `<`, `%` and quotes, and the O3
  prompt contains all of them.
- Binary paths are made absolute (bare names such as `claude` stay for PATH
  lookup). First CI run (35906840276): `hookconf bin` printed relative paths,
  the kit starts each harness with cwd=<run root>/project, and every Linux
  job raised FileNotFoundError; Pi failed on both OSes because node resolves
  its script argument (`cli.js`) against its own cwd. The Windows native
  binaries worked only because CreateProcess uses the parent's cwd. A binary
  that cannot start is now a start error that names the path and the cwd.
- Run roots: Linux uses the system temp dir (`/tmp`) when it is outside the
  home; CI sets `HOOKCONF_RUN_BASE=/tmp/hookconf-runs`.

Verified: the unit tests pass on Linux (WSL Ubuntu, Python 3.10.12, 95
passed, 1 skipped: the Windows-only shim test) and on Windows (96 passed). Not verified: a real harness
run on Linux; no harness is installed in WSL, and the first CI run is the
first Linux measurement.

## Isolation

Every harness session gets its own run root, and nothing outside it is
written:

- HOME, USERPROFILE, HOMEDRIVE/HOMEPATH, APPDATA, LOCALAPPDATA, XDG_*,
  TEMP/TMP, CLAUDE_CONFIG_DIR, CODEX_HOME, OPENCODE_TEST_HOME and
  PI_CODING_AGENT_DIR point into
  the run root. Drivers write config only through `assert_under(path, root)`,
  which also refuses any path in the real `~/.claude`, `~/.codex`, `~/.gemini`.
- The child environment is built from an allowlist (PATH, SYSTEMROOT, ...).
  Real API keys and the parent Claude Code session variables (CLAUDECODE,
  CLAUDE_CODE_*) never reach the harness; dummy keys are set. `check_env`
  raises if a non-dummy key or session variable is present.
- HTTP(S)_PROXY points at the mock server, which records every CONNECT and
  refuses it (403). The result lists these as "egress refused".
- Real config files (`~/.claude/settings*.json`, `~/.codex/config.toml`,
  `~/.codex/hooks.json`, `~/.gemini/...`) are checked by size and mtime
  before and after each session; any change raises.
- Leak check: if the harness output or any model request mentions the real
  `~/.claude`, `~/.codex`, `~/.gemini` or `~/.agents` path, the session raises.

Two more rules come from measured harness behavior (details in `docs/harness-notes.md`):

- Run roots live outside the real home (`HOOKCONF_RUN_BASE`, else the system temp dir if it is
  outside the home, else `C:\hookconf-runs` on Windows). The kit refuses a run root that is inside
  the home or has `.claude`, `.codex`, `.gemini` or `.agents` in any parent directory.
- Codex runs set `[skills] include_instructions = false` and `[features] skill_search = false`
  in the run's `config.toml`, so no skill from the real user profile reaches the model.

## Adding a harness

Write `hookconf/drivers/<name>.py` with a class that has:

- `name`, `probe_format` (`claude`, `codex`, or `plugin` for in-process
  hosts), `default_events`, `config_env_keys` (env vars that must point into
  the run root; the session asserts this), `hook_tool` (hook-side tool names
  for shell/write/edit/read), `tool_kinds`, `turn_id_field`,
  `has_fail_closed` + `fail_closed_note`, `bypass_flag`, `replace_mechanism`,
  `diagnostic_flags`, `prompt_last`.
- `version()`, `write_config(session)` (write only with `session.write`),
  `remove_hooks(session)`, `env(session)` (build on `isolation.build_env`),
  `command(session, prompt)`.
- Tool vocabulary for the mock: `shell`, `write_file`, `read_file`,
  `edit_file`, `subagent_plan`, `permission_shell`, `tamper_target`,
  `shell_replace`, and `diagnostics(stdout, stderr)`.
- Optional: `static_results` ({id: (status, note)}) for requirements that do
  not apply, `failure_kinds`, and `preflight(runner)` that returns a status for
  every check when the hook API is not called at all (see the OpenCode V2 and
  Warp drivers).

Register it in `hookconf/drivers/__init__.py`. If the harness speaks a model
API the mock does not have, add it to `hookconf/mockmodel.py` (today:
Anthropic Messages and OpenAI Responses, both streaming).
