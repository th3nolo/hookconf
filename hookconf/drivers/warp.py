"""Warp driver (static + opt-in live).

Warp has no agent hooks (survey [WA]: warpdotdev/warp source, HEAD e865a74;
single decision point BlocklistAIPermissions::can_autoexecute_command in
app/src/ai/blocklist/permissions.rs; the hooks draft PR #15832 / APP-4344 is
not shipped). Its model runs on Warp's servers, so no mock model is possible.

Default run (no harness process is started): every requirement is
`unsupported`, with static evidence from the installed binary (strings that a
hook system would need are absent; the agent-profile permission fields are
present). Nothing is executed, so no login, account or credit is used.

--live (opt-in, NOT run by the kit author): one harmless canary through
`oz agent run` with a profile whose command_denylist matches the canary. It
needs the owner's Warp login (`oz login`) or WARP_API_KEY, uses account
credits, and cannot be isolated with a temp HOME (credentials live in the
real profile). It refuses to start unless HOOKCONF_WARP_LIVE_ACCEPT=1 and
HOOKCONF_WARP_PROFILE (a profile id whose command_denylist contains
`echo HK-WARP-LIVE.*`) are set.
"""
from __future__ import annotations

import os
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_DIR = Path(os.path.expanduser(r"~\AppData\Local\Programs\Warp")) if os.name == "nt" else Path("/opt/warpdotdev/warp-terminal")

# Strings a hook system would need, and the permission fields Warp has instead.
HOOK_STRINGS = ["PreToolUse", "PostToolUse", "hooks.json", "agent_hooks", "permissionDecision", "hook_event_name"]
PERMISSION_STRINGS = ["command_denylist", "command_allowlist", "directory_allowlist", "mcp_allowlist", "mcp_denylist",
                      "auto_approve_bypasses_command_denylist", "execute_commands", "apply_code_diffs"]
SURVEY_SOURCE = ("docs/harness-hooks-survey.md [WA]: warpdotdev/warp source (HEAD e865a74) and draft PR #15832 "
                 "(APP-4344); decision point BlocklistAIPermissions::can_autoexecute_command, "
                 "app/src/ai/blocklist/permissions.rs, called from app/src/ai/blocklist/action_model/execute/"
                 "shell_command.rs should_autoexecute; outcomes: auto-run or not (user confirms in the app).")


def scan_binary(path: Path, needles: List[str]) -> Dict[str, int]:
    data = path.read_bytes()
    return {n: data.count(n.encode()) for n in needles}


class WarpDriver:
    name = "warp"
    gate_all = True  # the preflight result applies to every requirement id

    def __init__(self, binary: Optional[str] = None):
        self.dir = Path(binary).parent if binary else Path(os.environ.get("HOOKCONF_WARP_DIR", DEFAULT_DIR))
        self.binary = self.dir / ("warp.exe" if os.name == "nt" else "warp")

    def version(self) -> str:
        """Read from the binary, not by running it (`warp` without WARP_CLI_MODE opens the app)."""
        if not self.binary.is_file():
            return "not-installed"
        found = Counter(m.decode() for m in re.findall(rb"v0\.20\d\d\.\d\d\.\d\d\.\d\d\.\d\d\.[a-z]+_\d\d(?!\d)",
                                                      self.binary.read_bytes()))
        return found.most_common(1)[0][0] if found else "unknown"

    def preflight(self, rn: Any) -> tuple:
        from ..checks import UNSUPPORTED
        evidence: Dict[str, Any] = {"mode": "static (no process started, no account used)", "binary": str(self.binary),
                                    "survey_source": SURVEY_SOURCE,
                                    "shims": {p.name: p.read_text(encoding="utf-8", errors="replace")
                                              for p in (self.dir / "bin").glob("*.cmd")} if (self.dir / "bin").is_dir() else {}}
        if self.binary.is_file():
            evidence["hook_strings_in_binary"] = scan_binary(self.binary, HOOK_STRINGS)
            evidence["permission_fields_in_binary"] = scan_binary(self.binary, PERMISSION_STRINGS)
        summary = ("Warp has no agent hook system: no hook config, no hook events, no external decision. "
                   "The only controls are agent-profile allow/deny lists (command_allowlist, command_denylist, "
                   "directory_allowlist, MCP lists) and the app's confirm step. Static evidence; the live canary "
                   "(--live) was not run.")
        return (UNSUPPORTED, summary, evidence)

    # -- live probe (opt-in) ----------------------------------------------------
    def live_plan(self, workdir: str) -> Dict[str, Any]:
        marker = workdir.replace("\\", "/") + "/marker_warp_live.txt"
        prompt = f"Run exactly this shell command and nothing else, then stop: echo HK-WARP-LIVE > {marker}"
        oz = self.dir / "bin" / ("oz.cmd" if os.name == "nt" else "oz")
        argv = [str(oz), "agent", "run", "--prompt", prompt, "--cwd", workdir,
                "--profile", os.environ.get("HOOKCONF_WARP_PROFILE", "<profile id with command_denylist 'echo HK-WARP-LIVE.*'>")]
        return {"argv": argv, "marker": marker,
                "expect": "marker absent (denylist stops it) and no external hook is consulted; a second run with a "
                          "profile without the denylist entry should create the marker (control)",
                "needs": ["Warp login on this machine (`oz login`, reuses the app's credentials) or WARP_API_KEY",
                          "Warp account credits (the model runs on Warp's servers)",
                          "an agent profile id with command_denylist `echo HK-WARP-LIVE.*` (HOOKCONF_WARP_PROFILE)",
                          "HOOKCONF_WARP_LIVE_ACCEPT=1"],
                "isolation": "not isolatable with a temp HOME: credentials and profiles live in the real Warp profile"}

    def live_probe(self, workdir: str) -> Dict[str, Any]:
        plan = self.live_plan(workdir)
        if os.environ.get("HOOKCONF_WARP_LIVE_ACCEPT") != "1" or not os.environ.get("HOOKCONF_WARP_PROFILE"):
            plan["status"] = "refused: set HOOKCONF_WARP_LIVE_ACCEPT=1 and HOOKCONF_WARP_PROFILE to run it"
            return plan
        proc = subprocess.run(plan["argv"], capture_output=True, text=True, timeout=600, stdin=subprocess.DEVNULL)
        plan.update(status="ran", exit=proc.returncode, stdout_tail=proc.stdout[-2000:], stderr_tail=proc.stderr[-2000:],
                    marker_exists=os.path.exists(plan["marker"]))
        return plan
