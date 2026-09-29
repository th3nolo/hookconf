"""Pi driver (@earendil-works/pi-coding-agent, extension API, in-process).

Isolation: HOME, USERPROFILE, XDG_* and PI_CODING_AGENT_DIR point into the run
root (Pi's config dir defaults to ~/.pi/agent; docs/environment-variables.md).
PI_OFFLINE=1, PI_SKIP_VERSION_CHECK=1 and PI_TELEMETRY=0 stop startup network
calls.

Model: $PI_CODING_AGENT_DIR/models.json defines provider "hookconf" with
api "anthropic-messages" and baseUrl = the mock (Pi also supports
openai-completions, openai-responses, google-generative-ai; docs/models.md).

Hook: $PI_CODING_AGENT_DIR/extensions/hookconf_probe.ts (pi_extension.ts with
paths filled in): before_agent_start, tool_call (block / throw / ask via
ctx.ui.confirm), tool_result (replace content).

Pi has no permission modes, no PermissionRequest and no built-in subagents
(docs/usage.md: "It intentionally does not include built-in MCP, sub-agents,
permission popups, ..."). Every run is what other harnesses call bypass mode.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import probe as probe_module
from ..binpaths import absolute
from ..diag import failure_lines, json_lines, non_json_text
from ..isolation import build_env

KIT_DIR = Path(__file__).resolve().parent.parent.parent
PKG_DIR = KIT_DIR / "tools" / "pi" / "node_modules" / "@earendil-works" / "pi-coding-agent"
EXT_SRC = Path(__file__).with_name("pi_extension.ts")
NO_SUBAGENT = "Pi has no built-in subagent tool (docs/usage.md line 310: no built-in sub-agents; they are extension-provided)"


def fwd(p: Any) -> str:
    return str(p).replace("\\", "/")


class PiDriver:
    name = "pi"
    ready_pattern = r"\(hookconf\) mock"
    probe_format = "plugin"
    default_events: List[str] = []
    config_env_keys = ["PI_CODING_AGENT_DIR", "HOME", "USERPROFILE", "XDG_CONFIG_HOME"]
    hook_tool = {"shell": "bash", "write": "write", "edit": "edit", "read": "read"}
    tool_kinds = ("shell", "write", "edit", "read")
    turn_id_field = "prompt_entry_id"
    has_fail_closed = True
    fail_closed_note = ("Pi needs no setting: a tool_call handler that throws blocks the tool (docs/extensions.md, "
                        "Error Handling: 'tool_call errors block the tool (fail-safe)').")
    failure_kinds = ("crash", "hang")
    prompt_last = True
    diagnostic_flags: List[str] = []
    bypass_flag = "(none: Pi has no permission modes, every run executes tools without prompts)"
    replace_mechanism = "tool_result returns {content}"
    exit2_mechanism = "tool_call throws Error(reason) (in-process analog of exit 2 + stderr)"
    static_results = {
        # not_applicable only for an optional product feature (subagents); a missing permission capability
        # (P1 allow) is a gap, so it stays unsupported
        "O4": ("not_applicable", NO_SUBAGENT),
        "M3": ("not_applicable", NO_SUBAGENT),
        "P1": ("unsupported", "Pi has no permission prompts and no PermissionRequest event (docs/usage.md line 310)"),
    }

    def __init__(self, binary: Optional[str] = None):
        # absolute: node resolves the script argument against the child's cwd (the run root's project dir)
        self.cli = Path(absolute(binary or os.environ.get("HOOKCONF_PI_CLI") or PKG_DIR / "dist" / "bundle" / "cli.js"))
        self.node = shutil.which("node") or "node"
        self.binary = self.cli

    def version(self) -> str:
        """Read from package.json (no process start)."""
        try:
            return json.loads((self.cli.parent.parent.parent / "package.json").read_text(encoding="utf-8"))["version"]
        except (OSError, ValueError, KeyError):
            return "unknown"

    # -- config ---------------------------------------------------------------
    def agent_dir(self, session: Any) -> Path:
        return session.root.p("pi-agent")

    def config_path(self, session: Any) -> Path:
        return self.agent_dir(session) / "extensions" / "hookconf_probe.ts"

    def extension_source(self, session: Any, enabled: bool = True) -> str:
        src = EXT_SRC.read_text(encoding="utf-8")
        fills = {"__HOOKCONF_PYTHON__": fwd(sys.executable), "__HOOKCONF_PROBE__": fwd(probe_module.__file__),
                 "__HOOKCONF_LOG__": fwd(session.probe_log), "__HOOKCONF_SCENARIO__": fwd(session.scenario_path),
                 "__HOOKCONF_TMP__": fwd(session.root.p("tmp")),
                 "__HOOKCONF_ENABLED__": "true" if enabled else "false"}
        for k, v in fills.items():
            src = src.replace(k, v)
        return src

    def models_json(self, session: Any) -> Dict[str, Any]:
        return {"providers": {"hookconf": {
            "baseUrl": session.mock.url, "api": "anthropic-messages", "apiKey": "sk-ant-hookconf-dummy-key",
            "models": [{"id": "mock", "name": "hookconf mock", "reasoning": False, "input": ["text"],
                        "contextWindow": 200000, "maxTokens": 8192,
                        "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0}}]}}}

    def write_config(self, session: Any) -> Path:
        session.write("pi-agent/models.json", json.dumps(self.models_json(session), indent=1))
        session.write("pi-agent/settings.json", json.dumps({"defaultProjectTrust": "never"}, indent=1))
        return session.write("pi-agent/extensions/hookconf_probe.ts", self.extension_source(session))

    def remove_hooks(self, session: Any) -> Path:
        return session.write("pi-agent/extensions/hookconf_probe.ts", self.extension_source(session, enabled=False))

    def env(self, session: Any) -> Dict[str, str]:
        return build_env(session.root, session.mock.url, {
            "PI_CODING_AGENT_DIR": str(self.agent_dir(session)),
            "PI_OFFLINE": "1", "PI_SKIP_VERSION_CHECK": "1", "PI_TELEMETRY": "0",
        })

    def command(self, session: Any, prompt: str) -> List[str]:
        return [self.node, str(self.cli), "--mode", "json", "--provider", "hookconf", "--model", "mock", prompt]

    def interactive_command(self, session: Any) -> List[str]:
        return [self.node, str(self.cli), "--provider", "hookconf", "--model", "mock"]

    # -- tool vocabulary ------------------------------------------------------
    def shell(self, cmd: str) -> Dict[str, Any]:
        return {"name": "bash", "input": {"command": cmd}}

    def write_file(self, path: str, content: str) -> List[Dict[str, Any]]:
        return [{"calls": [{"name": "write", "input": {"path": path, "content": content}}]}]

    def read_file(self, path: str) -> Dict[str, Any]:
        return {"name": "read", "input": {"path": path}}

    def edit_file(self, path: str, old: str, new: str) -> List[Dict[str, Any]]:
        return [{"calls": [self.read_file(path)]},
                {"calls": [{"name": "edit", "input": {"path": path, "edits": [{"oldText": old, "newText": new}]}}]}]

    def subagent(self, script: str) -> Optional[Dict[str, Any]]:
        return None

    def subagent_plan(self, script: str) -> List[Any]:
        return [{"text": "HK-DONE"}]

    def permission_shell(self, cmd: str) -> Dict[str, Any]:
        return self.shell(cmd)

    def tamper_target(self, session: Any) -> Dict[str, str]:
        return {"path": fwd(self.config_path(session)),
                "edit_old": "// HOOKCONF_TAMPER_EDIT=no HOOKCONF_TAMPER_SHELL=no",
                "edit_new": "// HOOKCONF_TAMPER_EDIT=yes HOOKCONF_TAMPER_SHELL=no",
                "shell_old": "HOOKCONF_TAMPER_SHELL=no", "shell_new": "HOOKCONF_TAMPER_SHELL=yes"}

    def shell_replace(self, path: str, old: str, new: str) -> str:
        return f"sed -i 's/{old}/{new}/' '{path}'"

    def diagnostics(self, stdout: str, stderr: str) -> List[str]:
        out = []
        for obj in json_lines(stdout):
            typ = str(obj.get("type", ""))
            if "error" in typ.lower() or (typ.startswith("extension") and "error" in json.dumps(obj).lower()):
                out.append(json.dumps(obj)[:600])
        text = non_json_text(stdout) + "\n" + stderr
        return out + failure_lines(text) + [l for l in failure_lines(text.replace("xtension", "hook"))
                                            if l not in failure_lines(text)]
