# hookconf

hookconf tests whether an AI coding agent CLI obeys an external permission
hook. A permission hook is a program that the agent CLI calls before it runs
a tool (a shell command, a file write, a file edit). The hook answers allow,
deny or ask. A policy gate built on hooks is only as strong as the CLI's
support for them. hookconf measures that support from the outside.

It works like this:

1. It starts the real agent CLI (for example Claude Code or Codex) in a
   temporary folder, with a temporary home.
2. The CLI talks to a local mock model, not to a real model. The mock asks
   for fixed tool calls, for example `echo ... > marker.txt`.
3. A recording probe is installed as the CLI's hook. It answers with a fixed
   decision (deny, ask, allow or no opinion) and records what it received.
4. hookconf then checks the facts: did the marker file appear, what did the
   probe receive, what did the CLI send back to the mock model.

Each requirement gets a status (`pass`, `fail`, `unsupported`, `n/a`,
`not_tested`, `error`). The requirements roll up into a level, L0 to L4, per
CLI version.

## Levels

| Level | Meaning | Requirements |
|---|---|---|
| L0 Observe | The hook sees every tool call, with ids, the working folder and the prompt. | O1, O2, O3, O4 |
| L1 Block | A deny stops the tool, also in bypass mode, and the reason reaches the model. | B1, B2, B3, B4 |
| L2 Ask + context | An ask stops the tool until a person decides, also in bypass mode; the hook sees file content and the transcript. | A1, A2, A2b, A3, A4 |
| L3 Allow | The hook can approve a tool call that would otherwise need a prompt. | P1, P2, P3 |
| L4 Content + multi-agent | The hook can replace tool output; subagent calls carry an agent id and obey deny. | M1, M3 |

A CLI has level N when L0 to N are all met. Hardening items (fail-closed on
hook crash, no silent hook failure, hook config protected from the agent,
hooks fixed for the session, schema version, and more) are reported next to
the level as gaps. They do not lower the level. The exact rules, every
requirement and every status are in [`docs/reference.md`](docs/reference.md).

## Supported CLIs

| Harness id | CLI | How the hook is installed |
|---|---|---|
| `claude-code` | Claude Code | `settings.json` hooks in a temporary config folder |
| `codex` | OpenAI Codex CLI | `hooks.json` in a temporary `CODEX_HOME` |
| `opencode-v1` | OpenCode (plugin API) | plugin file in a temporary config folder |
| `opencode-v2` | OpenCode V2 | plugin file; measures whether the V2 tool hook fires |
| `pi` | Pi coding agent | extension file in a temporary agent folder |
| `warp` | Warp | static check of the installed app; starts no process |

## Requirements

- Python 3.10 or newer. hookconf uses only the standard library.
- The CLI you want to test, installed. Pass its path with `--bin PATH` or an
  environment variable (`HOOKCONF_CLAUDE_BIN`, `HOOKCONF_CODEX_BIN`,
  `HOOKCONF_OPENCODE_BIN`, `HOOKCONF_PI_CLI`, `HOOKCONF_WARP_DIR`).
  `python -m hookconf bin --harness <id> --prefix <npm dir>` finds the native
  binary inside an npm install.
- Node.js only for the CLIs that ship as npm packages.
- Windows or Linux. The results in `results/` were measured on Windows 11.
- For the unit tests: `pytest` (see `requirements-dev.txt`).

## No API key needed

The CLI under test talks only to the local mock model. hookconf sets dummy
keys, removes every other key from the CLI's environment, and points
`HTTP(S)_PROXY` at the mock, which refuses outbound connections. The run
fails if a real key reaches the CLI. No account, no credits, no network.

One optional mode needs a key: `hookconf e2e` installs the real semgate
policy gate as the hook, and semgate calls its classifier with the user's
own key. It is local only and refuses to run in CI. See
[`docs/reference.md`](docs/reference.md), "End-to-end mode".

## How to run

On Windows use `py` instead of `python`.

```
python -m hookconf list                                  # requirement ids and what each test does
python -m hookconf run --harness claude-code             # writes results/claude-code-<version>.json
python -m hookconf run --harness codex --only B1,B3      # a subset of requirements
python -m hookconf report results/*.json --md matrix.md  # the table of levels and gaps
```

A full run takes about 1 to 8 minutes per CLI. Every run gets its own run
root with the raw evidence (`probe.jsonl`, `mock.jsonl`, the CLI's stdout and
stderr); `--clean` deletes it after the checks.

Unit tests (no CLI needed; `tests/fake_harness.py` is a small stand-in agent):

```
python -m pip install -r requirements-dev.txt
python -m pytest -q tests
```

## Safety

hookconf starts real agent CLIs, so it keeps them away from your own setup:

- HOME, USERPROFILE, APPDATA, XDG folders, TEMP and each CLI's config
  variable point into the run root. The run root must be outside your home.
- Config is written only inside the run root. Your real `~/.claude`,
  `~/.codex` and `~/.gemini` files are checked before and after each session;
  any change stops the run.
- Every canary command is harmless if it runs: it writes a marker file inside
  the run root.

Details: [`docs/reference.md`](docs/reference.md), "Isolation".

## Layout

| Path | Content |
|---|---|
| `hookconf/` | the kit: runner, mock model, probe, checks, levels, report |
| `hookconf/drivers/` | one driver per CLI |
| `tests/` | unit tests |
| `results/` | measured result files |
| `ci/`, `.github/workflows/` | CI with pinned CLI versions (no secrets used) |
| `docs/reference.md` | full description: requirements, statuses, levels, CI, adding a CLI |

## License

Apache License 2.0. See `LICENSE` and `NOTICE`. Third-party tools that the
kit runs or installs in CI are listed in `THIRD_PARTY_NOTICES.md`.
