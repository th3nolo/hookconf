"""Codex CLI driver.

Config: $CODEX_HOME/config.toml defines a custom model provider (wire_api =
"responses") that points at the mock server; hooks go in $CODEX_HOME/hooks.json.
Both files are inside the run root. `codex exec` runs headless with
--dangerously-bypass-hook-trust, because hook trust is stored per hook hash
and a fresh CODEX_HOME has none (the flag is recorded in every session argv).

On Windows Codex runs hook commands through PowerShell, so the Windows
command uses the call operator: & "python.exe" "probe.py" ...

Modes:
  default  -s danger-full-access (exec approval policy is "never"). Note: on
           Windows with a fresh CODEX_HOME, -s workspace-write behaves as
           read-only (shell and apply_patch writes are rejected), so a
           control canary could not run in it.
  bypass   --dangerously-bypass-approvals-and-sandbox
  strict   --approve-for-me (workspace-write sandbox; an escalated command needs
           an approval, which is where PermissionRequest fires)
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..binpaths import check_launchable
from ..diag import failure_lines, json_lines, non_json_text
from ..isolation import build_env
from ..mockmodel import tool_results

DEFAULT_BIN = os.path.expanduser(r"~\AppData\Local\Programs\OpenAI\Codex\bin\codex.exe") if os.name == "nt" else "codex"
MODEL = "gpt-5.5"
NAMESPACE = "multi_agent_v1"


class CodexDriver:
    name = "codex"
    probe_format = "codex"
    default_events = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "PermissionRequest", "SubagentStart", "SubagentStop"]
    config_env_keys = ["CODEX_HOME", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"]
    hook_tool = {"shell": "Bash", "write": "apply_patch", "edit": "apply_patch", "read": "Bash"}
    tool_kinds = ("shell", "write", "edit")
    turn_id_field = "turn_id"
    has_fail_closed = False
    fail_closed_note = "Codex has no fail-closed option: hook errors, timeouts and non-zero exits are advisory (hooks docs, Failure Behavior)."
    prompt_last = True
    diagnostic_flags: List[str] = []
    replace_mechanism = "decision=block + reason"
    bypass_flag = "--dangerously-bypass-approvals-and-sandbox"

    def __init__(self, binary: Optional[str] = None):
        self.binary = str(check_launchable(binary or os.environ.get("HOOKCONF_CODEX_BIN") or shutil.which("codex")
                                           or DEFAULT_BIN))

    def version(self) -> str:
        out = subprocess.run([self.binary, "--version"], capture_output=True, text=True, timeout=60)
        parts = out.stdout.strip().split()
        return parts[-1] if parts else "unknown"

    # -- config ---------------------------------------------------------------
    def config_path(self, session: Any) -> Path:
        return session.root.p("codex", "hooks.json")

    def _cmd(self, session: Any, event: str) -> Dict[str, Any]:
        cmd = session.probe_command(event)
        # Windows: Codex runs the hook through PowerShell -Command, which exits 1 for any
        # failed native command unless the exit code is passed on explicitly (exit 2 would be lost).
        return {"type": "command", "command": cmd, "commandWindows": "& " + cmd + "; exit $LASTEXITCODE",
                "timeout": session.hook_timeout}

    def hooks_doc(self, session: Any, with_hooks: bool = True) -> Dict[str, Any]:
        doc: Dict[str, Any] = {"description": "HOOKCONF_TAMPER_EDIT=no HOOKCONF_TAMPER_SHELL=no"}
        doc["hooks"] = {ev: [{"matcher": "*", "hooks": [self._cmd(session, ev)]}] for ev in session.events} if with_hooks else {}
        return doc

    def write_config(self, session: Any) -> Path:
        session.write("codex/config.toml", "\n".join([
            f'model = "{MODEL}"',
            'model_provider = "hookconf"',
            "check_for_update_on_startup = false",
            "",
            "[model_providers.hookconf]",
            'name = "hookconf mock"',
            f'base_url = "{session.mock.url}/v1"',
            'env_key = "HOOKCONF_DUMMY_KEY"',
            'wire_api = "responses"',
            "",
            "# Codex 0.153.1 on Windows finds <real profile>/.agents/skills through the OS",
            "# profile lookup, which ignores HOME/USERPROFILE. Keep those skills out of the",
            "# prompt and out of skill search (see docs/reference.md, isolation).",
            "[skills]",
            "include_instructions = false",
            "",
            "[features]",
            "skill_search = false",
            "",
        ]))
        return session.write("codex/hooks.json", json.dumps(self.hooks_doc(session), indent=1))

    def remove_hooks(self, session: Any) -> Path:
        return session.write("codex/hooks.json", json.dumps(self.hooks_doc(session, with_hooks=False), indent=1))

    def env(self, session: Any) -> Dict[str, str]:
        return build_env(session.root, session.mock.url, {"CODEX_HOME": str(session.root.p("codex"))})

    def command(self, session: Any, prompt: str) -> List[str]:
        argv = [self.binary, "exec", "--skip-git-repo-check", "--dangerously-bypass-hook-trust", "--json"]
        if session.mode == "bypass":
            argv.append(self.bypass_flag)
        elif session.mode == "strict":
            # `codex exec` forces approval policy Never ("you cannot ask for escalated
            # permissions if the approval policy is Never"); --approve-for-me is the only
            # headless path where an approval request exists.
            # (it cannot be combined with -s; it uses the workspace-write sandbox).
            argv += ["--approve-for-me"]
        else:
            argv += ["-s", "danger-full-access"]
        return argv + [prompt]

    # -- tool vocabulary ------------------------------------------------------
    def shell(self, cmd: str, escalate: bool = False) -> Dict[str, Any]:
        args: Dict[str, Any] = {"cmd": cmd}
        if escalate:
            args.update({"sandbox_permissions": "require_escalated", "justification": "hookconf canary"})
        return {"name": "exec_command", "input": args}

    @staticmethod
    def _patch(body: str) -> str:
        return "*** Begin Patch\n" + body + "*** End Patch\n"

    def write_file(self, path: str, content: str) -> List[Dict[str, Any]]:
        lines = "".join("+" + ln + "\n" for ln in content.splitlines())
        return [{"calls": [{"name": "apply_patch", "kind": "custom", "input": self._patch(f"*** Add File: {path}\n{lines}")}]}]

    def read_file(self, path: str) -> Dict[str, Any]:
        return self.shell(f"cat '{path}'")

    def edit_file(self, path: str, old: str, new: str) -> List[Dict[str, Any]]:
        """old/new are whole lines."""
        return [{"calls": [{"name": "apply_patch", "kind": "custom",
                            "input": self._patch(f"*** Update File: {path}\n@@\n-{old}\n+{new}\n")}]}]

    def subagent(self, script: str) -> Optional[Dict[str, Any]]:
        return {"name": "spawn_agent", "namespace": NAMESPACE, "input": {"message": f"HKSCRIPT:{script} run the scripted steps"}}

    def subagent_plan(self, script: str) -> List[Any]:
        """Multi-agent tools are deferred: load them with tool_search, spawn, then wait."""
        def wait_step(rec: Dict[str, Any]) -> Dict[str, Any]:
            results = tool_results(rec["body"])
            text = results[-1]["text"] if results else ""
            ids = re.findall(r'"agent_id"\s*:\s*"([^"]+)"', text)
            return {"calls": [{"name": "wait_agent", "namespace": NAMESPACE, "input": {"targets": ids[:1], "timeout_ms": 60000}}]}
        return [{"calls": [{"name": "tool_search", "kind": "tool_search", "input": {"query": "spawn sub-agent", "limit": 8}}]},
                {"calls": [self.subagent(script)]}, wait_step, {"text": "HK-DONE"}]

    def permission_shell(self, cmd: str) -> Dict[str, Any]:
        """In strict mode (read-only, on-request) a write needs an escalation, which needs approval."""
        return self.shell(cmd, escalate=True)

    def tamper_target(self, session: Any) -> Dict[str, str]:
        path = str(self.config_path(session)).replace("\\", "/")
        return {"path": path,
                "edit_old": ' "description": "HOOKCONF_TAMPER_EDIT=no HOOKCONF_TAMPER_SHELL=no",',
                "edit_new": ' "description": "HOOKCONF_TAMPER_EDIT=yes HOOKCONF_TAMPER_SHELL=no",',
                "shell_old": "HOOKCONF_TAMPER_SHELL=no", "shell_new": "HOOKCONF_TAMPER_SHELL=yes"}

    def shell_replace(self, path: str, old: str, new: str) -> str:
        if os.name == "nt":  # Codex uses PowerShell on Windows
            return f"(Get-Content -Raw '{path}') -replace '{old}','{new}' | Set-Content -NoNewline '{path}'"
        return f"sed -i 's/{old}/{new}/' '{path}'"

    def diagnostics(self, stdout: str, stderr: str) -> List[str]:
        """Hook failures Codex reports: `--json` error items and warnings other than
        the fixed --dangerously-bypass-hook-trust notice, plus plain-text lines
        that mention a hook and a failure word."""
        out = []
        for obj in json_lines(stdout):
            item = obj.get("item") if isinstance(obj.get("item"), dict) else obj
            if item.get("type") in ("error", "warning") or obj.get("type") in ("error", "warning"):
                msg = json.dumps(item)
                if "dangerously-bypass-hook-trust" not in msg:
                    out.append(msg[:600])
        text = non_json_text(stdout) + "\n" + stderr
        return out + [l for l in failure_lines(text) if "dangerously-bypass-hook-trust" not in l]
