"""Claude Code driver.

Config: hooks go in $CLAUDE_CONFIG_DIR/settings.json (user scope), inside the
run root. The model endpoint is ANTHROPIC_BASE_URL -> mock server.

Modes:
  default  permissions.allow = Bash, Write, Edit, Read: the harness would run
           the canary without any hook (proved by control sessions)
  bypass   --dangerously-skip-permissions
  bypass_settings
           settings.json permissions.defaultMode = "bypassPermissions", no flag
           (A2b; the stream-json init record shows the active permissionMode)
  strict   no allow rules: headless -p denies anything that needs a prompt
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..binpaths import check_launchable, git_bash_env
from ..diag import failure_lines, json_lines, non_json_text
from ..isolation import build_env

DEFAULT_BIN = os.path.expanduser(r"~\.local\bin\claude.exe") if os.name == "nt" else "claude"
BYPASS_SETTING = "bypassPermissions"


class ClaudeCodeDriver:
    name = "claude-code"
    probe_format = "claude"
    default_events = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "PermissionRequest", "SubagentStart", "SubagentStop"]
    config_env_keys = ["CLAUDE_CONFIG_DIR", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA"]
    # names the hook sees for each tool kind
    hook_tool = {"shell": "Bash", "write": "Write", "edit": "Edit", "read": "Read"}
    tool_kinds = ("shell", "write", "edit", "read")
    turn_id_field = "prompt_id"
    has_fail_closed = False
    fail_closed_note = "Claude Code has no fail-closed option: a crash or non-zero exit other than 2 is non-blocking (hooks docs, exit code section)."
    prompt_last = False
    diagnostic_flags = ["--include-hook-events"]
    replace_mechanism = "hookSpecificOutput.updatedToolOutput shaped like tool_response"
    bypass_flag = "--dangerously-skip-permissions"
    # every way to enter bypass mode headless (A2b runs ask in each)
    bypass_modes = [("bypass", "--dangerously-skip-permissions"),
                    ("bypass_settings", 'settings permissions.defaultMode "bypassPermissions"')]

    def __init__(self, binary: Optional[str] = None):
        self.binary = str(check_launchable(binary or os.environ.get("HOOKCONF_CLAUDE_BIN") or shutil.which("claude")
                                           or DEFAULT_BIN))

    # -- identity -------------------------------------------------------------
    def version(self) -> str:
        out = subprocess.run([self.binary, "--version"], capture_output=True, text=True, timeout=60,
                             env={k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "ANTHROPIC"))})
        return out.stdout.strip().split()[0] if out.stdout.strip() else "unknown"

    # -- config ---------------------------------------------------------------
    def config_path(self, session: Any) -> Path:
        return session.root.p("config", "settings.json")

    def settings(self, session: Any, with_hooks: bool = True) -> Dict[str, Any]:
        s: Dict[str, Any] = {"env": {"HOOKCONF_TAMPER_EDIT": "no", "HOOKCONF_TAMPER_SHELL": "no"}}
        if session.mode != "strict":
            s["permissions"] = {"allow": ["Bash", "Write", "Edit", "Read"]}
        if session.mode == "bypass_settings":
            s["permissions"]["defaultMode"] = BYPASS_SETTING
        if with_hooks:
            s["hooks"] = {ev: [{"matcher": "*", "hooks": [{"type": "command", "command": session.probe_command(ev),
                                                           "timeout": session.hook_timeout}]}]
                          for ev in session.events}
        return s

    def write_config(self, session: Any) -> Path:
        return session.write("config/settings.json", json.dumps(self.settings(session), indent=1))

    def remove_hooks(self, session: Any) -> Path:
        """Mid-session config change for A6: same file, hooks removed."""
        return session.write("config/settings.json", json.dumps(self.settings(session, with_hooks=False), indent=1))

    def env(self, session: Any) -> Dict[str, str]:
        mock = session.mock
        return build_env(session.root, mock.url, {
            "CLAUDE_CONFIG_DIR": str(session.root.p("config")),
            "ANTHROPIC_BASE_URL": mock.url,
            "DISABLE_AUTOUPDATER": "1", "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            **git_bash_env("CLAUDE_CODE_GIT_BASH_PATH"),  # Windows only
        })

    def command(self, session: Any, prompt: str) -> List[str]:
        argv = [self.binary, "-p", prompt, "--output-format", "stream-json", "--verbose", "--max-turns", "12"]
        if session.mode == "bypass":
            argv.append(self.bypass_flag)
        return argv

    @staticmethod
    def mode_evidence(stdout: str) -> Dict[str, Any]:
        """permissionMode from the stream-json init record; permission_denials from the result record."""
        out: Dict[str, Any] = {"permissionMode": None}
        for obj in json_lines(stdout):
            if obj.get("type") == "system" and obj.get("subtype") == "init":
                out["permissionMode"] = obj.get("permissionMode")
            elif obj.get("type") == "result":
                out["permission_denials"] = obj.get("permission_denials")
        return out

    @staticmethod
    def bypass_active(seen: Dict[str, Any]) -> Optional[bool]:
        mode = seen.get("permissionMode")
        return None if mode is None else mode == BYPASS_SETTING

    # -- tool vocabulary (what the mock model asks for) -----------------------
    def shell(self, cmd: str) -> Dict[str, Any]:
        return {"name": "Bash", "input": {"command": cmd, "description": "hookconf canary"}}

    def write_file(self, path: str, content: str) -> List[Dict[str, Any]]:
        return [{"calls": [{"name": "Write", "input": {"file_path": path, "content": content}}]}]

    def read_file(self, path: str) -> Dict[str, Any]:
        return {"name": "Read", "input": {"file_path": path}}

    def edit_file(self, path: str, old: str, new: str) -> List[Dict[str, Any]]:
        """Steps; Claude Code requires a Read of the file before an Edit."""
        return [{"calls": [self.read_file(path)]},
                {"calls": [{"name": "Edit", "input": {"file_path": path, "old_string": old, "new_string": new}}]}]

    def subagent(self, script: str) -> Optional[Dict[str, Any]]:
        return {"name": "Agent", "input": {"description": "hookconf subagent", "subagent_type": "general-purpose",
                                           "prompt": f"HKSCRIPT:{script} run the scripted steps"}}

    def subagent_plan(self, script: str) -> List[Any]:
        return [{"calls": [self.subagent(script)]}, {"text": "HK-DONE"}]

    def permission_shell(self, cmd: str) -> Dict[str, Any]:
        """Shell call that needs a permission decision in strict mode."""
        return self.shell(cmd)

    def tamper_target(self, session: Any) -> Dict[str, str]:
        """File that holds the hooks, with two harmless markers to flip."""
        return {"path": str(self.config_path(session)).replace("\\", "/"),
                "edit_old": '"HOOKCONF_TAMPER_EDIT": "no"', "edit_new": '"HOOKCONF_TAMPER_EDIT": "yes"',
                "shell_old": '"HOOKCONF_TAMPER_SHELL": "no"', "shell_new": '"HOOKCONF_TAMPER_SHELL": "yes"'}

    def shell_replace(self, path: str, old: str, new: str) -> str:
        # Git Bash sed; the strings contain no single quotes or slashes
        return f"sed -i 's/{old}/{new}/' '{path}'"

    def diagnostics(self, stdout: str, stderr: str) -> List[str]:
        """Hook failures the harness reports in its own output.

        stream-json: `system/hook_response` records (emitted only with
        --include-hook-events) whose outcome is not success or whose exit code is
        not 0 or 2. Plain text: lines that mention a hook and a failure word.
        """
        out = []
        for obj in json_lines(stdout):
            if obj.get("type") == "system" and obj.get("subtype") == "hook_response":
                if obj.get("outcome") not in ("success", None) or obj.get("exit_code") not in (0, 2, None):
                    out.append(f"hook_response {obj.get('hook_name')} outcome={obj.get('outcome')} exit_code={obj.get('exit_code')}")
            elif obj.get("type") == "system" and "hook" in str(obj.get("subtype", "")) and "error" in json.dumps(obj).lower():
                out.append(json.dumps(obj)[:600])
        return out + failure_lines(non_json_text(stdout) + "\n" + stderr)
