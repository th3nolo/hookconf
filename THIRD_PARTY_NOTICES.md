# Third-party notices

hookconf contains no third-party source code and ships no third-party
binaries. The tools below are only run by hookconf, or installed by its CI
workflow from the npm registry and PyPI. They are not part of this
repository and are not redistributed. Each one stays under its own license.

## Agent CLIs under test

| Tool | Package (CI pin) | License | How hookconf uses it |
|---|---|---|---|
| Claude Code | `@anthropic-ai/claude-code` 2.1.278 | proprietary, Anthropic's terms ("SEE LICENSE IN README.md") | runs the installed CLI; CI installs it with `npm ci --ignore-scripts` |
| OpenAI Codex CLI | `@openai/codex` 0.155.1 | Apache-2.0 | runs the installed CLI; CI installs it |
| OpenCode | `opencode-ai` 1.18.31 | MIT | runs the installed CLI; CI installs it |
| Pi coding agent | `@earendil-works/pi-coding-agent` 0.86.1 | MIT (its dependencies: MIT, Apache-2.0, BSD-3-Clause, ISC, BlueOak-1.0.0, 0BSD, Unlicense) | runs the installed CLI; CI installs it |
| Warp | desktop app | proprietary, Warp's terms | reads the installed app's files (static check); never started by hookconf; not installed in CI |

The lockfiles in `ci/npm/*/package-lock.json` list every package with its
version, source URL and integrity hash. They are data for `npm ci`, not
copies of the packages.

## Test and CI tools

| Tool | Version | License |
|---|---|---|
| pytest | 9.1.1 | MIT |
| iniconfig | 2.3.0 | MIT |
| packaging | 26.0 | Apache-2.0 or BSD-2-Clause |
| pluggy | 1.6.0 | MIT |
| pygments | 2.19.2 | BSD-2-Clause |
| colorama | 0.4.6 | BSD-3-Clause |
| GitHub Actions `actions/checkout`, `setup-python`, `setup-node`, `upload-artifact`, `download-artifact` | pinned by SHA in `.github/workflows/conformance.yml` | MIT |

## Formats

The mock model speaks the Anthropic Messages and OpenAI Responses streaming
formats, and the probe reads each CLI's documented hook payload. hookconf
implements these formats from their public documentation; it copies no code
from the vendors.
