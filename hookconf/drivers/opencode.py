"""OpenCode driver (plugin API, in-process).

Isolation: HOME, USERPROFILE, OPENCODE_TEST_HOME, XDG_CONFIG_HOME,
XDG_DATA_HOME, XDG_CACHE_HOME and XDG_STATE_HOME all point into the run root.
OpenCode resolves its global config dir as $XDG_CONFIG_HOME/opencode and its
home as OPENCODE_TEST_HOME ?? os.homedir() (read from the 1.18.31 binary).
OPENCODE_DISABLE_CLAUDE_CODE / _EXTERNAL_SKILLS stop it from reading
~/.claude and other agents' skills; OPENCODE_DISABLE_MODELS_FETCH,
_AUTOUPDATE, _DEFAULT_PLUGINS, _LSP_DOWNLOAD stop network installs.

Model: a custom provider in $XDG_CONFIG_HOME/opencode/opencode.json using the
bundled @ai-sdk/anthropic package with baseURL = the mock (Anthropic Messages).

Hook: $XDG_CONFIG_HOME/opencode/plugins/hookconf_probe.js (opencode_plugin.js
with paths filled in). Variant v1 exports server() (hooks object:
tool.execute.before/after, chat.message, permission.ask); variant v2 exports
setup(ctx) and registers ctx.tool.hook("execute.before").

Modes (the `permission` block in opencode.json):
  default  bash/edit/read/external_directory = allow (control canary runs)
  bypass   same rules as strict, plus `opencode run --auto` (auto-approve
           everything not explicitly denied)
  strict   bash/edit = ask: headless `opencode run` has no one to ask
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import probe as probe_module
from ..binpaths import candidates, check_launchable, git_bash_env
from ..diag import failure_lines, json_lines, non_json_text
from ..isolation import build_env

KIT_DIR = Path(__file__).resolve().parent.parent.parent
PLUGIN_SRC = Path(__file__).with_name("opencode_plugin.js")


def default_bin() -> str:
    """Platform binary in tools/opencode (installed without install scripts); first existing candidate."""
    cands = candidates("opencode", KIT_DIR / "tools" / "opencode")
    return str(next((p for p in cands if p.is_file()), cands[0]))


def fwd(p: Any) -> str:
    return str(p).replace("\\", "/")


class OpenCodeDriver:
    name = "opencode-v1"
    variant = "v1"
    probe_format = "plugin"
    default_events: List[str] = []  # the plugin registers its own events
    config_env_keys = ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "HOME", "USERPROFILE", "OPENCODE_TEST_HOME"]
    hook_tool = {"shell": "bash", "write": "write", "edit": "edit", "read": "read"}
    tool_kinds = ("shell", "write", "edit", "read")
    turn_id_field = "prompt_message_id"
    has_fail_closed = True
    fail_closed_note = ("OpenCode needs no setting: a plugin that throws blocks the tool call (the throw is the deny "
                        "mechanism), and a plugin that never returns stalls the call.")
    failure_kinds = ("crash", "hang")
    prompt_last = False  # the prompt is several trailing words; extra flags go before them via command()
    diagnostic_flags: List[str] = []
    replace_mechanism = "tool.execute.after: output.output = replacement"
    exit2_mechanism = ("tool.execute.before throws Error(reason) (in-process analog of exit 2 + stderr; "
                       "for OpenCode this is also its deny mechanism)")
    bypass_flag = "--auto"
    static_results = {
        "A2": ("unsupported", "the V1 tool.execute.before hook has no ask value (it can only return or throw); "
                              "the ask path is permission.ask, see P1"),
        "A2b": ("unsupported", "the V1 tool.execute.before hook has no ask value (it can only return or throw), "
                               "so there is no ask to honor under --auto either; see A2"),
    }

    def __init__(self, binary: Optional[str] = None):
        self.binary = str(check_launchable(binary or os.environ.get("HOOKCONF_OPENCODE_BIN") or default_bin()))

    def version(self) -> str:
        import subprocess
        out = subprocess.run([self.binary, "--version"], capture_output=True, text=True, timeout=120,
                             env={k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "ANTHROPIC", "OPENAI"))})
        return out.stdout.strip().split()[-1] if out.stdout.strip() else "unknown"

    # -- config ---------------------------------------------------------------
    def config_dir(self, session: Any) -> Path:
        return session.root.p("xdg", "config", "opencode")

    def config_path(self, session: Any) -> Path:
        return self.config_dir(session) / "plugins" / "hookconf_probe.js"

    def plugin_source(self, session: Any, enabled: bool = True) -> str:
        src = PLUGIN_SRC.read_text(encoding="utf-8")
        fills = {"__HOOKCONF_VARIANT__": self.variant, "__HOOKCONF_PYTHON__": fwd(sys.executable),
                 "__HOOKCONF_PROBE__": fwd(probe_module.__file__), "__HOOKCONF_LOG__": fwd(session.probe_log),
                 "__HOOKCONF_SCENARIO__": fwd(session.scenario_path), "__HOOKCONF_TMP__": fwd(session.root.p("tmp"))}
        for k, v in fills.items():
            src = src.replace(k, v)
        return src.replace("__HOOKCONF_ENABLED__", "true" if enabled else "false")

    def opencode_json(self, session: Any) -> Dict[str, Any]:
        if session.mode == "default":
            perm = {"bash": "allow", "edit": "allow", "read": "allow", "external_directory": "allow", "task": "allow"}
        else:
            perm = {"bash": "ask", "edit": "ask", "read": "allow", "external_directory": "ask", "task": "allow"}
        return {
            "model": "hookconf/mock", "small_model": "hookconf/mock", "autoupdate": False, "share": "disabled",
            "provider": {"hookconf": {"npm": "@ai-sdk/anthropic", "name": "hookconf mock",
                                      "options": {"baseURL": session.mock.url + "/v1", "apiKey": "sk-ant-hookconf-dummy-key"},
                                      "models": {"mock": {"name": "mock", "tool_call": True, "attachment": False,
                                                          "reasoning": False, "temperature": True,
                                                          "limit": {"context": 200000, "output": 8192}}}}},
            "permission": perm,
        }

    def write_config(self, session: Any) -> Path:
        base = "xdg/config/opencode/"
        session.write(base + "opencode.json", json.dumps(self.opencode_json(session), indent=1))
        return session.write(base + "plugins/hookconf_probe.js", self.plugin_source(session))

    def remove_hooks(self, session: Any) -> Path:
        """A6: the same plugin file, rewritten to export no hooks."""
        return session.write("xdg/config/opencode/plugins/hookconf_probe.js", self.plugin_source(session, enabled=False))

    def env(self, session: Any) -> Dict[str, str]:
        home = str(session.root.p("home"))
        return build_env(session.root, session.mock.url, {
            "OPENCODE_TEST_HOME": home,
            "OPENCODE_DISABLE_AUTOUPDATE": "1", "OPENCODE_DISABLE_MODELS_FETCH": "1",
            "OPENCODE_DISABLE_CLAUDE_CODE": "1", "OPENCODE_DISABLE_EXTERNAL_SKILLS": "1",
            "OPENCODE_DISABLE_DEFAULT_PLUGINS": "1", "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
            "OPENCODE_DISABLE_SHARE": "1",
            **git_bash_env("OPENCODE_GIT_BASH_PATH"),  # Windows only
        })

    def command(self, session: Any, prompt: str) -> List[str]:
        argv = [self.binary, "run", "--format", "json", "--model", "hookconf/mock"]
        if session.mode == "bypass":
            argv.append(self.bypass_flag)
        # `opencode run` joins the message words with spaces and wraps a word that
        # contains a space in literal double quotes (measured on 1.18.31), so pass the
        # prompt as separate words, the way a shell would split what a user types.
        return argv + prompt.split(" ")

    # -- preflight ------------------------------------------------------------
    def preflight(self, rn: Any) -> Optional[tuple]:
        """One session: is the plugin API for this variant called at all?"""
        from ..checks import UNSUPPORTED, probe_ev
        s = rn.new_session("preflight")
        res = s.run({"main": [{"calls": [self.shell("echo HK-PREFLIGHT")]}, {"text": "HK-DONE"}]}, {"rules": [], "default": "none"})
        loaded = [r for r in res.probe if r.get("event") == "PluginLoaded"]
        log_lines = []
        for f in sorted(s.root.p("xdg", "data", "opencode", "log").glob("*.log")):
            log_lines += [l[:500] for l in f.read_text(encoding="utf-8", errors="replace").splitlines()
                          if "plugin" in l.lower() and ("ERROR" in l or "WARN" in l)]
        pre = res.events("PreToolUse")
        rn._sessions["preflight"] = res
        if loaded and pre:
            return None
        if loaded:
            keys = (loaded[0].get("payload") or {}).get("ctx_keys")
            why = (f"OpenCode {self.version()} called the {self.variant} entry point"
                   + (f" (ctx keys: {', '.join(keys)}; no `tool`, so ctx.tool.hook cannot be registered)" if keys else "")
                   + " but no tool hook fired")
        else:
            why = f"OpenCode {self.version()} never called the {self.variant} plugin entry point"
        rejected = [l for l in log_lines if "failed to load plugin" in l]
        if rejected:
            why += "; it then rejected the plugin, reported only in its log file (" + rejected[0].split("error=", 1)[-1][:160] + ")"
        return (UNSUPPORTED, why + "; the shell tool ran with no hook event",
                {"plugin_loaded_events": probe_ev(loaded), "probe_events": probe_ev(res.probe),
                 "opencode_log_plugin_lines": log_lines[:10], "stdout_stderr_mentions_plugin":
                     [l[:300] for l in (res.stdout + res.stderr).splitlines() if "plugin" in l.lower()][:5],
                 "tool_ran": "HK-PREFLIGHT" in json.dumps([r.get("body") for r in res.model_requests()])})

    # -- tool vocabulary ------------------------------------------------------
    def shell(self, cmd: str) -> Dict[str, Any]:
        return {"name": "bash", "input": {"command": cmd, "description": "hookconf canary"}}

    def write_file(self, path: str, content: str) -> List[Dict[str, Any]]:
        return [{"calls": [{"name": "write", "input": {"filePath": path, "content": content}}]}]

    def read_file(self, path: str) -> Dict[str, Any]:
        return {"name": "read", "input": {"filePath": path}}

    def edit_file(self, path: str, old: str, new: str) -> List[Dict[str, Any]]:
        """OpenCode requires a read of the file before an edit."""
        return [{"calls": [self.read_file(path)]},
                {"calls": [{"name": "edit", "input": {"filePath": path, "oldString": old, "newString": new}}]}]

    def subagent(self, script: str) -> Optional[Dict[str, Any]]:
        return {"name": "task", "input": {"description": "hookconf subagent", "subagent_type": "general",
                                          "prompt": f"HKSCRIPT:{script} run the scripted steps"}}

    def subagent_plan(self, script: str) -> List[Any]:
        return [{"calls": [self.subagent(script)]}, {"text": "HK-DONE"}]

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
            if obj.get("type") == "error" or (isinstance(obj.get("error"), (dict, str)) and "plugin" in json.dumps(obj).lower()):
                out.append(json.dumps(obj)[:600])
        text = non_json_text(stdout) + "\n" + stderr
        return out + failure_lines(text) + [l for l in failure_lines(text.replace("plugin", "hook"))
                                            if l not in failure_lines(text)]


class OpenCodeV2Driver(OpenCodeDriver):
    name = "opencode-v2"
    variant = "v2"
    static_results = dict(OpenCodeDriver.static_results)
    static_results["A2"] = ("unsupported", "the V2 execute.before hook has no ask effect in this kit's probe; "
                                           "#47495 reports that effect \"ask\" is ignored")
    static_results["A2b"] = ("unsupported", "no ask effect in the V2 hook (see A2), so none under --auto either")
