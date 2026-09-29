"""One harness invocation against the mock model, in its own temp root."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import probe as probe_module
from .isolation import IsolationError, RunRoot, assert_under, diff_snapshots, snapshot_real_configs
from .mockmodel import MockModel, tool_results
from .pty import Exchange, run as run_pty

MAX_STR = 1500
KIT_EVENTS = ("PluginLoaded", "HangEnd", "AskOutcome")  # kit bookkeeping records, not harness hook events


def fwd(p: Any) -> str:
    return str(p).replace("\\", "/")


def trim(obj: Any, limit: int = MAX_STR) -> Any:
    """Shorten long strings inside a JSON-like value (for evidence)."""
    if isinstance(obj, str):
        return obj if len(obj) <= limit else obj[:limit] + f"...[+{len(obj) - limit} chars]"
    if isinstance(obj, list):
        return [trim(x, limit) for x in obj]
    if isinstance(obj, dict):
        return {k: trim(v, limit) for k, v in obj.items()}
    return obj


@dataclass
class SessionResult:
    sid: str
    root: str
    argv: List[str]
    mode: str
    exit: Optional[int]
    duration_s: float
    stdout: str
    stderr: str
    probe: List[Dict[str, Any]]
    records: List[Dict[str, Any]]
    timed_out: bool = False
    isolation_diff: Dict[str, Any] = field(default_factory=dict)
    terminal: Dict[str, Any] = field(default_factory=dict)

    # -- queries ------------------------------------------------------------
    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def events(self, event: Optional[str] = None, tool: Optional[str] = None) -> List[Dict[str, Any]]:
        out = []
        for r in self.probe:
            if r.get("hang_end") or r.get("event") in KIT_EVENTS:
                continue
            if event and r.get("event") != event:
                continue
            if tool and (r.get("payload") or {}).get("tool_name") != tool:
                continue
            out.append(r)
        return out

    def model_requests(self, script: Optional[str] = None) -> List[Dict[str, Any]]:
        return [r for r in self.records if r.get("kind") == "main" and (script is None or r.get("script") == script)]

    def results_text(self, script: Optional[str] = None) -> List[Dict[str, Any]]:
        """Tool results in the last model request of `script` (what the model saw)."""
        reqs = self.model_requests(script)
        return tool_results(reqs[-1]["body"]) if reqs else []

    def egress(self) -> List[str]:
        return [f"{r.get('method')} {r.get('path')}" for r in self.records if r.get("kind") == "egress"]

    def summary(self) -> Dict[str, Any]:
        return {"sid": self.sid, "root": self.root, "argv": self.argv, "mode": self.mode, "exit": self.exit,
                "duration_s": round(self.duration_s, 2), "timed_out": self.timed_out,
                "model_requests": len(self.model_requests()), "probe_events": len(self.probe),
                "egress_refused": self.egress(), "isolation_diff": self.isolation_diff,
                "unknown_requests": [f"{r.get('method')} {r.get('path')}" for r in self.records if r.get("kind") == "unknown"],
                "terminal": self.terminal,
                "stdout_tail": trim(self.stdout[-1200:]), "stderr_tail": trim(self.stderr[-1200:])}


def real_config_mentions(text: str) -> List[str]:
    """Real-home agent config paths that appear in `text` (a leak signal)."""
    home = str(Path(os.path.expanduser("~")))
    variants = {home, home.replace("\\", "/"), home.replace("\\", "\\\\")}
    found = []
    for h in variants:
        for name in (".claude", ".codex", ".gemini", ".agents"):
            for sep in ("/", "\\", "\\\\"):
                needle = h + sep + name
                if needle in text and needle not in found:
                    found.append(needle)
    return found


class HarnessStartError(RuntimeError):
    """The harness never reached the mock model, so no check can use the session."""


class Session:
    """Allocates a temp root; the driver writes config into it; run() executes."""

    def __init__(self, driver: Any, sid: str, mode: str = "default", hook_timeout: int = 30,
                 events: Optional[List[str]] = None, keep: bool = True, run_timeout: int = 240,
                 extra_args: Optional[List[str]] = None):
        self.driver = driver
        self.sid = sid
        self.mode = mode
        self.hook_timeout = hook_timeout
        self.events = list(events or driver.default_events)
        self.root = RunRoot(prefix=f"hookconf-{driver.name}-{sid}-", keep=keep)
        self.run_timeout = run_timeout
        self.extra_args = list(extra_args or [])
        self.probe_log = self.root.p("probe.jsonl")
        self.scenario_path = self.root.p("scenario.json")
        self.hook_config: Optional[Path] = None
        self.mock: Optional[MockModel] = None

    def path(self, rel: str) -> str:
        """Absolute path (forward slashes) inside the run root."""
        return fwd(assert_under(self.root.p(*rel.split("/")), self.root.path))

    def project(self, rel: str) -> str:
        return self.path("project/" + rel)

    def write(self, rel: str, text: str) -> Path:
        return self.root.write(rel, text)

    def probe_command(self, event: str) -> str:
        return (f'"{fwd(sys.executable)}" "{fwd(probe_module.__file__)}" --event {event} '
                f'--log "{fwd(self.probe_log)}" --scenario "{fwd(self.scenario_path)}" --format {self.driver.probe_format}')

    def set_scenario(self, scenario: Dict[str, Any]) -> None:
        self.write("scenario.json", json.dumps(scenario, indent=1))

    def run(self, plans: Dict[str, List[Any]], scenario: Dict[str, Any], prompt: str = "",
            script: str = "main", setup: Optional[Callable[["Session"], None]] = None,
            exchanges: Optional[List[Exchange]] = None) -> SessionResult:
        before = snapshot_real_configs()
        self.set_scenario(scenario)
        self.mock = MockModel(plans=plans, log_path=str(self.root.p("mock.jsonl"))).start()
        try:
            self.hook_config = self.driver.write_config(self)
            assert_under(self.hook_config, self.root.path)
            env = self.driver.env(self)
            for key in self.driver.config_env_keys:
                assert_under(env[key], self.root.path)
            if setup:
                setup(self)
            text = prompt or f"HKSCRIPT:{script} run the scripted steps"
            interactive = exchanges is not None
            if interactive:
                env = dict(env, TERM="xterm-256color")
            argv = self.driver.interactive_command(self) if interactive else self.driver.command(self, text)
            if self.extra_args:  # flags go before the trailing prompt for harnesses that take it last
                argv = (argv[:-1] + self.extra_args + argv[-1:]
                        if not interactive and self.driver.prompt_last else argv + self.extra_args)
            start = time.time()
            timed_out = False
            terminal = {}
            try:
                if interactive:
                    terminal_result = run_pty(argv, cwd=str(self.root.p("project")), env=env,
                                              exchanges=[Exchange(self.driver.ready_pattern, text + "\r", timeout_s=30)] + exchanges,
                                              timeout_s=self.run_timeout)
                    code, out, err = terminal_result.exit, terminal_result.output.encode("utf-8"), b""
                    timed_out = terminal_result.timed_out
                    terminal = {"backend": terminal_result.backend, "matched": terminal_result.matched,
                                "pending": terminal_result.pending}
                else:
                    proc = subprocess.run(argv, cwd=str(self.root.p("project")), env=env, stdin=subprocess.DEVNULL,
                                          capture_output=True, timeout=self.run_timeout)
                    code = proc.returncode
                    out, err = proc.stdout, proc.stderr
            except subprocess.TimeoutExpired as exc:
                timed_out, code = True, None
                out, err = exc.stdout or b"", exc.stderr or b""
            except OSError as exc:  # binary missing or not executable: say which path and which cwd
                raise HarnessStartError(f"session {self.sid}: cannot start {argv[0]!r} (cwd {self.root.p('project')}): "
                                        f"{type(exc).__name__}: {exc}") from exc
            duration = time.time() - start
            time.sleep(0.3)  # let late probe writes land
        finally:
            self.mock.stop()
        probe_records = []
        if self.probe_log.exists():
            for line in self.probe_log.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    probe_records.append(json.loads(line))
        diff = diff_snapshots(before, snapshot_real_configs())
        result = SessionResult(sid=self.sid, root=str(self.root.path), argv=[str(a) for a in argv], mode=self.mode, exit=code,
                               duration_s=duration, stdout=out.decode("utf-8", "replace"), stderr=err.decode("utf-8", "replace"),
                               probe=probe_records, records=list(self.mock.records), timed_out=timed_out, isolation_diff=diff,
                               terminal=terminal)
        (self.root.p("harness.stdout")).write_bytes(out)
        (self.root.p("harness.stderr")).write_bytes(err)
        if diff:
            raise IsolationError(f"real config files changed during session {self.sid}: {diff}")
        blob = result.stdout + result.stderr + json.dumps(result.records)
        leaks = real_config_mentions(blob)
        if leaks:
            raise IsolationError(f"session {self.sid}: harness output or model requests mention real config dirs {leaks}; "
                                 f"the harness read the real home (see {self.root.path})")
        if not result.model_requests():
            raise HarnessStartError(f"session {self.sid}: the harness made no scripted model request (exit {code}); "
                                    f"stderr: {result.stderr[-600:]!r}")
        return result
