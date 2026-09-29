"""End-to-end mode: real harness + real semgate hook + real Jev, mock model.

    py -m hookconf e2e --harness claude-code --harness opencode-v1 \
        --semgate-python C:/path/to/semgate/.venv/Scripts/python.exe \
        --semgate-policy C:/path/to/semgate/policies/router_policy_dev.json

The conformance run (`hookconf run`) answers the harness's hook with a
recording probe that gives fixed answers. This mode keeps the mock model and
the drivers, but installs semgate itself as the hook with `semgate init
<host>` into the run root, so the decision comes from semgate's rules, gates
and the TypeSafe (Jev) classifier. Local only: it needs a TypeSafe key, which
semgate loads itself (its provider reads the key from its own source
checkout's .env or ~/.semgate/.env). The kit never reads, passes or logs the
key; `check_env` still refuses any non-dummy key in the child environment.

Per case (hookconf/e2e_cases.py), in its own run root:
  1. control session (default on): same case, no hook. The canary must fire,
     or the case is `error` (the kit could not tell).
  2. semgate session: `semgate init` writes semgate.json, grant.json and the
     host's hook file into the run root; the harness runs; the kit reads
     semgate's ledger in the run root (judgment + host_response records) and
     what the harness sent back to the mock model.
  status pass: semgate's outcome for the target call is one of the expected
  outcomes AND the harness obeyed it (the canary fired exactly when semgate
  allowed).

Isolation on top of Session's own checks: HOME, USERPROFILE and every store
path point into the run root; `semgate init` runs with SEMGATE_WRITE_ROOT =
the run root; the real ~/.semgate, ~/.config/opencode (config files and
plugins/) and <semgate checkout>/.antigravity are snapshotted before and after
each session (RealWatch). Only the Jev API host is added to NO_PROXY; every
other request still goes to the mock's proxy sink.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from . import __version__
from .checks import result_for
from .diag import json_lines
from .e2e_cases import BASE_FILES
from .isolation import IsolationError, RunRoot, assert_under, build_env, real_home
from .runner import KIT_DIR, kit_git_sha
from .session import Session, SessionResult, fwd, trim

# harness name -> `semgate init <host>` name. Codex and Pi: semgate has no adapter.
SEMGATE_HOSTS = {"claude-code": "claude", "opencode-v1": "opencode", "opencode-v2": "opencode"}
PURPOSE = "Software development in this project: read, edit, build, test"
DONE_TEXT = "E2E-DONE"
LOCAL_ONLY_VARS = ("CI", "GITHUB_ACTIONS")


class E2EError(RuntimeError):
    pass


def refuse_in_ci(environ: Optional[Dict[str, str]] = None) -> Optional[str]:
    """A reason to refuse when running in CI (the mode needs a TypeSafe key)."""
    environ = os.environ if environ is None else environ
    hits = [v for v in LOCAL_ONLY_VARS if str(environ.get(v, "")).strip().lower() in ("1", "true", "yes")]
    if hits:
        return f"hookconf e2e is local only (needs a TypeSafe key); refusing because {', '.join(hits)} is set"
    return None


# ---------------------------------------------------------------------------
# semgate install into a run root

PREFLIGHT = r"""
import json, os
out = {}
import semgate
out["semgate_file"] = semgate.__file__
out["semgate_version"] = str(getattr(semgate, "__version__", ""))
from typesafe_sdk.constants import DEFAULT_BASE_URL
out["jev_base_url"] = DEFAULT_BASE_URL
import dotenv  # noqa: F401  (semgate's provider reads the key with it)
from semgate.providers.typesafe import TypeSafeProvider
TypeSafeProvider()
out["key_found"] = bool(os.environ.get("TYPESAFE_API_KEY", "").strip())
print(json.dumps(out))
"""


def no_proxy_with(env: Dict[str, str], host: str) -> Dict[str, str]:
    """env with `host` added to NO_PROXY / no_proxy (everything else still uses the proxy sink)."""
    out = dict(env)
    for key in ("NO_PROXY", "no_proxy"):
        hosts = [h for h in str(out.get(key, "")).split(",") if h.strip()]
        if host not in hosts:
            hosts.append(host)
        out[key] = ",".join(hosts)
    return out


def patch_config(cfg: Dict[str, Any], auto_allow_bash: bool, block_when_unsure: bool) -> Dict[str, Any]:
    """The run's posture on top of what `semgate init --mode enforce` wrote."""
    out = json.loads(json.dumps(cfg))
    enf = out.setdefault("enforcement", {})
    tools = [str(t) for t in enf.get("auto_allow_tools", [])]
    if auto_allow_bash and "bash" not in tools:
        tools.append("bash")
    if not auto_allow_bash:
        tools = [t for t in tools if t != "bash"]
    enf["auto_allow_tools"] = tools
    enf["block_when_unsure"] = bool(block_when_unsure)
    return out


STORE_KEYS = (("ledger_file",), ("grant_file",), ("auto_allow_learned", "history_file"), ("feedback", "feedback_file"),
              ("enforcement", "deny_escalation", "state_file"), ("tool_outputs", "dir"), ("secret_exposures", "dir"),
              ("secret_exposures", "key_file"), ("agent_files", "dir"), ("profiles", "state_file"))


def store_paths(cfg: Dict[str, Any]) -> List[str]:
    out = []
    for keys in STORE_KEYS:
        node: Any = cfg
        for k in keys:
            node = node.get(k) if isinstance(node, dict) else None
        if isinstance(node, str) and node.strip():
            out.append(node)
    return out


class SemgateInstall:
    """Installs real semgate as the hook of one run root (`semgate init`)."""

    def __init__(self, python: str, policy: str, block_when_unsure: bool = True, auto_allow_bash: bool = True,
                 purpose: str = PURPOSE):
        self.python = os.path.abspath(python)
        self.policy = os.path.abspath(policy)
        self.block_when_unsure = block_when_unsure
        self.auto_allow_bash = auto_allow_bash
        self.purpose = purpose
        self.facts: Dict[str, Any] = {}

    @property
    def jev_host(self) -> str:
        return urlparse(str(self.facts.get("jev_base_url", ""))).hostname or ""

    def posture(self) -> Dict[str, Any]:
        return {"mode": "enforce", "provider": "typesafe", "policy": fwd(self.policy),
                "auto_allow_bash": self.auto_allow_bash, "block_when_unsure": self.block_when_unsure,
                "purpose": self.purpose}

    def preflight(self) -> Dict[str, Any]:
        """semgate, typesafe-sdk and python-dotenv import from the interpreter, and
        semgate's provider finds a key (prints only true/false, never the key)."""
        if not os.path.isfile(self.python):
            raise E2EError(f"--semgate-python {self.python} does not exist")
        if not os.path.isfile(self.policy):
            raise E2EError(f"--semgate-policy {self.policy} does not exist")
        root = RunRoot(prefix="hookconf-e2e-preflight-", keep=False)
        try:
            env = build_env(root, "http://127.0.0.1:9")  # no network needed; a dead proxy refuses any attempt
            proc = subprocess.run([self.python, "-c", PREFLIGHT], env=env, cwd=str(root.p("project")),
                                  capture_output=True, text=True, timeout=120)
        finally:
            root.cleanup()
        if proc.returncode != 0:
            raise E2EError(f"semgate preflight failed with {self.python} (exit {proc.returncode}): {proc.stderr[-800:]}")
        try:
            facts = json.loads(proc.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            raise E2EError(f"semgate preflight printed no JSON: {proc.stdout[-400:]!r}")
        if not facts.get("key_found"):
            raise E2EError("semgate's TypeSafe provider found no TYPESAFE_API_KEY (semgate reads it from its own "
                           "checkout's .env or ~/.semgate/.env); e2e needs it")
        self.facts = facts
        return facts

    def env_patch(self, env: Dict[str, str]) -> Dict[str, str]:
        if not self.jev_host:
            raise E2EError("preflight() did not run: the Jev API host is unknown")
        return no_proxy_with(env, self.jev_host)

    def install(self, session: Session, harness: str, hooks_file: Path) -> Dict[str, Any]:
        """`semgate init <host>` into the run root, then the posture patch.
        Returns facts for the result (paths, init output tail, the posture)."""
        host = SEMGATE_HOSTS[harness]
        root = session.root
        target = root.p("semgate")
        assert_under(hooks_file, root.path)
        argv = [self.python, "-m", "semgate", "init", host, "--dir", str(target), "--hooks-file", str(hooks_file),
                "--project", str(root.p("project")), "--mode", "enforce", "--policy", self.policy,
                "--purpose", self.purpose, "--force"]
        # SEMGATE_WRITE_ROOT: semgate's own guard refuses any write outside the run root.
        # USERNAME/USER: `semgate init` writes getpass.getuser() into grant.json, which raises
        # OSError on Windows when no user variable is set (the allowlisted env has none).
        env = build_env(root, session.mock.url if session.mock else "http://127.0.0.1:9",
                        {"SEMGATE_WRITE_ROOT": str(root.path), "USERNAME": "hookconf-e2e", "USER": "hookconf-e2e"})
        proc = subprocess.run(argv, env=env, cwd=str(root.p("project")), capture_output=True, text=True, timeout=180)
        if proc.returncode != 0:
            raise E2EError(f"semgate init {host} failed (exit {proc.returncode}): {(proc.stdout + proc.stderr)[-1200:]}")
        cfg_path = target / "semgate.json"
        cfg = patch_config(json.loads(cfg_path.read_text(encoding="utf-8")), self.auto_allow_bash, self.block_when_unsure)
        for p in store_paths(cfg):
            assert_under(p, root.path)  # every store semgate writes is in the run root
        root.write("semgate/semgate.json", json.dumps(cfg, indent=2) + "\n")
        if not Path(hooks_file).is_file():
            raise E2EError(f"semgate init {host} did not write {hooks_file}")
        return {"host": host, "config": fwd(cfg_path), "hooks_file": fwd(hooks_file), "ledger": fwd(cfg.get("ledger_file", "")),
                "init_argv": [fwd(a) for a in argv], "init_output_tail": trim((proc.stdout + proc.stderr)[-1500:]),
                "enforcement": cfg.get("enforcement", {})}


# ---------------------------------------------------------------------------
# driver wrapper: the harness driver with semgate (or nothing) as its hook

class SemgateDriver:
    """Delegates to a harness driver; replaces the probe with semgate.

    install=None is the control: the same base config with no hook at all.
    """

    def __init__(self, inner: Any, install: Optional[SemgateInstall]):
        self.inner = inner
        self.install = install
        self.installed: Dict[str, Any] = {}

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def _base(self, session: Session) -> Tuple[Path, Path]:
        """Write the harness config without the kit's probe. Returns (config file, hooks file)."""
        if hasattr(self.inner, "opencode_json"):   # OpenCode: opencode.json + a plugin file
            base = session.write("xdg/config/opencode/opencode.json", json.dumps(self.inner.opencode_json(session), indent=1))
            return base, session.root.p("xdg", "config", "opencode", "plugins", "semgate.js")
        settings = self.inner.settings(session, with_hooks=False)   # Claude Code family: settings.json
        path = session.write("config/settings.json", json.dumps(settings, indent=1))
        return path, path

    @property
    def is_opencode(self) -> bool:
        return hasattr(self.inner, "opencode_json")

    def write_config(self, session: Session) -> Path:
        base, hooks_file = self._base(session)
        if self.install is None:
            return base
        self.installed = self.install.install(session, self.inner.name, hooks_file)
        return Path(hooks_file)

    def env(self, session: Session) -> Dict[str, str]:
        """The driver's isolated env, plus (semgate session) the Jev host in NO_PROXY.

        OpenCode 1.18.31 removes HTTP_PROXY, HTTPS_PROXY and NO_PROXY (any case)
        from the environment of the processes it starts (bash tool, plugin
        children) and keeps only all_proxy (measured: `env` in its bash tool).
        semgate's serve process then sends the Jev call to the mock's sink.
        So for OpenCode ALL_PROXY is dropped too: its children get no proxy at
        all. curl, the only network command in the cases, is kept on the sink
        by a .curlrc in the temp home (written for every harness).

        OpenCode 1.18.31 on Windows runs its shell tool in Windows PowerShell
        5.1 unless SHELL names a shell (measured: its bash tool description says
        "Shell: powershell"; with SHELL = Git Bash it says "Shell: bash" and
        $BASH_VERSION is set). The cases are bash commands (Claude Code runs
        them in Git Bash), so SHELL is set to the Git Bash path the driver
        already gives OpenCode (OPENCODE_GIT_BASH_PATH)."""
        env = self.inner.env(session)
        if self.is_opencode:
            for key in ("ALL_PROXY", "all_proxy"):
                env.pop(key, None)
            if env.get("OPENCODE_GIT_BASH_PATH"):
                env["SHELL"] = env["OPENCODE_GIT_BASH_PATH"]
        write_curlrc(session)
        return self.install.env_patch(env) if self.install is not None else env

    def command(self, session: Session, prompt: str) -> List[str]:
        """OpenCode's `run` parses words of the message that start with "-" as its
        own flags (`-s` is --session: "Session not found"); "--" ends the flags.
        After "--" a numeric word ("755") reaches OpenCode as a number and `run`
        crashes ("G.includes is not a function", 1.18.31); then the whole prompt
        goes as one argument after "--" (OpenCode wraps it in literal quotes)."""
        argv = self.inner.command(session, prompt)
        words = prompt.split(" ")
        if self.is_opencode and any(w.startswith("-") for w in words) and argv[-len(words):] == words:
            numeric = any(re.fullmatch(r"-?\d+(\.\d+)?", w) for w in words)
            argv = argv[:-len(words)] + ["--"] + ([prompt] if numeric else words)
        return argv


def write_curlrc(session: Session) -> None:
    """curl's config file in every place curl looks for it under the temp home
    (HOME/.curlrc, Windows: %APPDATA%/_curlrc and %USERPROFILE%/_curlrc,
    XDG_CONFIG_HOME/.curlrc): every curl request goes to the mock's proxy sink,
    which records it (the egress canary) and refuses it."""
    text = f'proxy = "{session.mock.url}"\n'
    for rel in ("home/.curlrc", "home/_curlrc", "appdata/_curlrc", "xdg/config/.curlrc"):
        session.write(rel, text)


# ---------------------------------------------------------------------------
# real-home watch (on top of Session's snapshot of ~/.claude, ~/.codex, ~/.gemini)

LOG_SUFFIXES = (".jsonl", ".lock", ".log")


def watch_roots(home: Path, semgate_checkout: Optional[Path]) -> List[Tuple[Path, bool]]:
    """(path, recursive). ~/.config/opencode is large (node_modules): only its
    top-level files and plugins/ are watched."""
    out = [(home / ".semgate", True), (home / ".config" / "opencode", False),
           (home / ".config" / "opencode" / "plugins", True)]
    if semgate_checkout is not None:
        out.append((semgate_checkout / ".antigravity", True))
    return out


def snapshot_files(roots: Iterable[Tuple[Path, bool]]) -> Dict[str, Tuple[int, int]]:
    out: Dict[str, Tuple[int, int]] = {}
    for base, recursive in roots:
        if not base.is_dir():
            continue
        entries = base.rglob("*") if recursive else base.iterdir()
        for p in entries:
            try:
                if p.is_file():
                    st = p.stat()
                    out[str(p)] = (st.st_size, st.st_mtime_ns)
            except OSError:
                continue
    return out


def _needles(run_root: str) -> List[str]:
    r = str(run_root)
    return sorted({r, r.replace("\\", "/"), r.replace("\\", "\\\\"), r.lower(), r.replace("\\", "/").lower()})


def compare_watch(before: Dict[str, Tuple[int, int]], after: Dict[str, Tuple[int, int]],
                  run_root: str) -> Tuple[List[str], List[str]]:
    """(problems, notes). A changed or new file is a problem, except a log file
    (.jsonl/.lock/.log) whose new bytes do not mention the run root: that is
    another agent on this machine writing its own log (a note). A removed file
    is a problem."""
    problems, notes = [], []
    for path in sorted(set(before) | set(after)):
        b, a = before.get(path), after.get(path)
        if b == a:
            continue
        if a is None:
            problems.append(f"removed during the session: {path}")
            continue
        if not path.lower().endswith(LOG_SUFFIXES):
            problems.append(f"changed during the session: {path} {b} -> {a}")
            continue
        start = b[0] if b and a[0] >= b[0] else 0
        try:
            with open(path, "rb") as fh:
                fh.seek(start)
                added = fh.read(20 * 1024 * 1024).decode("utf-8", "replace")
        except OSError as exc:
            problems.append(f"changed and unreadable: {path}: {exc}")
            continue
        low = added.lower()
        if any(n.lower() in low for n in _needles(run_root)):
            problems.append(f"real store {path} got records that mention this run root")
        else:
            notes.append(f"{path} changed (no mention of this run root: another agent's log)")
    return problems, notes


# ---------------------------------------------------------------------------
# analysis (pure functions over a finished session)

def read_ledger(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not path or not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("{"):
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    return out


def target_call_ids(records: List[Dict[str, Any]], step: int) -> List[str]:
    """Tool call ids the mock sent when it answered `step` (a retried request gets new ids)."""
    ids: List[str] = []
    for r in records:
        if r.get("kind") == "main" and r.get("step") == step:
            ids.extend(str(i) for i in r.get("response_ids") or [])
    return ids


# semgate (5d04123+) puts this in front of a block a chat reply can never approve
# (human gate untrusted_instruction: the command came from content the agent read).
NOT_CHAT_APPROVABLE = "It cannot be approved in chat"


def category(host_decision: str, judge_decision: str, host_reason: str = "") -> str:
    """runs | asked | blocked, from what semgate returned to the host and what
    the judge decided. A host deny whose judgment was not a deny is an ask the
    host could not show (block_when_unsure, manifest C2, Devin mapping), unless
    semgate says the deny can never be approved in chat: that is a block."""
    if host_decision == "allow":
        return "runs"
    if judge_decision == "deny":
        return "blocked"
    if host_decision == "deny" and NOT_CHAT_APPROVABLE in host_reason:
        return "blocked"
    return "asked"


def _call_matches(envelope: Dict[str, Any], kind: str, arg: str) -> bool:
    args = ((envelope or {}).get("action") or {}).get("arguments") or {}
    if kind == "shell":
        return str(args.get("command", "")).strip() == arg.strip()
    path = str(args.get("path") or args.get("file_path") or args.get("filePath") or "").replace("\\", "/")
    return bool(path) and path.endswith(arg)


def semgate_verdict(ledger: List[Dict[str, Any]], ids: List[str], kind: str, arg: str) -> Optional[Dict[str, Any]]:
    """semgate's answer for the target call: the host_response for one of `ids`
    (the harness's tool call id) and its judgment (same envelope digest).
    Fallback when the host's step id is not the model's call id: the last
    judgment whose action is the target call."""
    judgments = [r for r in ledger if r.get("record_type") == "judgment"]
    responses = [r for r in ledger if r.get("record_type") == "host_response"]
    hr = next((r for r in reversed(responses) if str(r.get("step_idx")) in ids), None)
    jd = None
    if hr is not None:
        jd = next((j for j in reversed(judgments) if j.get("judgment_id") == hr.get("content_digest")), None)
    if hr is None:
        jd = next((j for j in reversed(judgments) if _call_matches(j.get("envelope") or {}, kind, arg)), None)
        if jd is not None:
            hr = next((r for r in reversed(responses) if r.get("content_digest") == jd.get("judgment_id")), None)
    if hr is None and jd is None:
        return None
    native = (hr or {}).get("native") or {}
    dec = (jd or {}).get("decision") or {}
    host_decision = str(native.get("decision", ""))
    judge_decision = str(dec.get("decision", ""))
    return {
        "host_decision": host_decision,
        "host_reason": trim(str(native.get("reason", "")), 1200),
        "judge": {"decision": judge_decision, "stage": dec.get("stage", ""), "reason_code": dec.get("reason_code", ""),
                  "gate_hits": [h.get("gate") or h.get("id") or h.get("name") or json.dumps(h)[:80]
                                for h in dec.get("gate_hits") or [] if isinstance(h, dict)],
                  "reasons": [trim(str(x), 400) for x in (dec.get("reasons") or [])][:6],
                  "error": dec.get("error"), "latency_ms": dec.get("latency_ms")},
        "matched_by": "call id" if hr is not None and str(hr.get("step_idx")) in ids else "command",
        "category": category(host_decision, judge_decision, str(native.get("reason", ""))) if hr is not None else "unknown",
    }


def model_saw(res: SessionResult, ids: List[str]) -> Optional[Dict[str, Any]]:
    """The tool result the harness sent back to the mock model for the target call."""
    for cid in ids:
        tr = result_for(res, cid)
        if tr is not None:
            return {"text": trim(tr["text"], 1500), "is_error": tr["is_error"]}
    return None


def canary_fired(canary: Dict[str, str], root: Path, res: SessionResult, saw: Optional[Dict[str, Any]]) -> bool:
    kind, value = next(iter(canary.items()))
    project = root / "project"
    if kind in ("file", "absent", "writable"):
        path = assert_under(project.joinpath(*value.split("/")), root)
        if kind == "file":
            return path.exists()
        if kind == "absent":
            return not path.exists()
        return path.exists() and bool(path.stat().st_mode & stat.S_IWRITE)
    if kind == "output":
        return bool(saw) and value in saw["text"] and not saw.get("is_error", False)
    if kind == "egress":
        return any(value in e for e in res.egress())
    raise ValueError(f"unknown canary kind {kind!r}")


def hook_stdouts(stdout: str) -> List[str]:
    """Claude Code --include-hook-events: what each PreToolUse hook printed, in order."""
    return [str(o.get("stdout", "")).strip() for o in json_lines(stdout)
            if o.get("type") == "system" and o.get("subtype") == "hook_response" and o.get("hook_event") == "PreToolUse"]


def answer_format(hook_stdout: str) -> str:
    """Which host format a Claude-family hook answer is in: claude
    (hookSpecificOutput.permissionDecision), devin ({"decision": approve|block}),
    copilot (top-level permissionDecision), or unknown."""
    try:
        obj = json.loads(hook_stdout)
    except ValueError:
        return "unknown"
    if not isinstance(obj, dict):
        return "unknown"
    if isinstance(obj.get("hookSpecificOutput"), dict):
        return "claude"
    if obj.get("decision") in ("approve", "block"):
        return "devin"
    if "permissionDecision" in obj:
        return "copilot"
    return "unknown"


def judge_case(expect: List[str], verdict: Optional[Dict[str, Any]], fired: bool,
               control_fired: Optional[bool]) -> Tuple[str, str]:
    """(status, note). status: pass | fail | error."""
    if control_fired is False:
        return "error", "the canary did not fire in the control run (no hook), so this run cannot tell whether the call ran"
    if verdict is None or verdict["category"] == "unknown":
        if fired:
            return "fail", "the call ran and semgate recorded no answer for it (the hook did not judge it)"
        return "error", "semgate recorded no answer for the call and the call did not run (hook missing or harness stopped)"
    cat = verdict["category"]
    obeyed = (cat == "runs") == fired
    if not obeyed:
        what = "ran although semgate did not allow it" if fired else "did not run although semgate allowed it"
        return "fail", f"harness did not follow semgate: the call {what} (semgate {verdict['host_decision']})"
    if cat not in expect:
        return "fail", f"semgate outcome {cat} ({verdict['host_decision']}; judge {verdict['judge']['stage']}/" \
                       f"{verdict['judge']['decision']} {verdict['judge']['reason_code']}) not in expected {expect}"
    return "pass", ""


# ---------------------------------------------------------------------------
# sessions

def plan_for(driver: Any, case: Dict[str, Any], project: str) -> List[Any]:
    steps: List[Any] = []
    for kind, arg in case["steps"]:
        if kind == "shell":
            steps.append({"calls": [driver.shell(arg)]})
        elif kind == "read":
            steps.append({"calls": [driver.read_file(project.rstrip("/") + "/" + arg)]})
        else:
            raise ValueError(f"unknown step kind {kind!r}")
    return steps + [{"text": DONE_TEXT}]


def make_setup(case: Dict[str, Any]) -> Callable[[Session], None]:
    spec = case.get("setup") or {}

    def setup(session: Session) -> None:
        files = dict(BASE_FILES)
        files.update(spec.get("files") or {})
        for rel, text in files.items():
            session.write("project/" + rel, text)
        for rel in spec.get("readonly") or []:
            os.chmod(assert_under(session.root.p("project", *rel.split("/")), session.root.path), 0o444)
        if spec.get("git_init"):
            env = build_env(session.root, session.mock.url, {"GIT_CONFIG_NOSYSTEM": "1"})
            subprocess.run(["git", "init", "-q"], cwd=str(session.root.p("project")), env=env, check=True,
                           capture_output=True, timeout=60)
    return setup


def make_writable(root: Path) -> None:
    """Read-only canary files would stop rmtree on Windows."""
    for p in root.rglob("*"):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD | (stat.S_IEXEC if p.is_dir() else 0))
        except OSError:
            pass


class CaseRun:
    """One case on one harness: optional control session, then the semgate session."""

    def __init__(self, driver: Any, install: SemgateInstall, case: Dict[str, Any], keep: bool = True,
                 control: bool = True, watch: Optional[List[Tuple[Path, bool]]] = None,
                 log: Callable[[str], None] = print, run_timeout: int = 300):
        self.driver = driver
        self.install = install
        self.case = case
        self.keep = keep
        self.control = control
        self.watch = watch or []
        self.log = log
        self.run_timeout = run_timeout

    def _session(self, sid: str, install: Optional[SemgateInstall]) -> Tuple[SemgateDriver, Session]:
        wrapped = SemgateDriver(self.driver, install)
        extra = list(getattr(self.driver, "diagnostic_flags", []) or []) if install is not None else []
        return wrapped, Session(wrapped, sid, keep=True, run_timeout=self.run_timeout, extra_args=extra)

    def _run(self, sid: str, install: Optional[SemgateInstall]) -> Tuple[SemgateDriver, Session, SessionResult, List[str]]:
        wrapped, s = self._session(sid, install)
        before = snapshot_files(self.watch)
        try:
            res = s.run({"": plan_for(self.driver, self.case, s.project(""))}, {"rules": [], "default": "none"},
                        prompt=self.case["prompt"], setup=make_setup(self.case))
        finally:
            problems, notes = compare_watch(before, snapshot_files(self.watch), str(s.root.path))
            if problems:
                raise IsolationError(f"session {sid}: " + "; ".join(problems))
        return wrapped, s, res, notes

    def run(self) -> Dict[str, Any]:
        case = self.case
        target = case.get("target", len(case["steps"]) - 1)
        kind, arg = case["steps"][target]
        out: Dict[str, Any] = {"id": case["id"], "prompt": case["prompt"],
                               "steps": [{"tool": k, "arg": a} for k, a in case["steps"]], "target_step": target,
                               "expect": list(case["expect"]), "canary": case["canary"], "harmless": case["harmless"]}
        sessions: List[Session] = []
        try:
            control_fired: Optional[bool] = None
            if self.control:
                _, cs, cres, _ = self._run(f"e2e_{case['id']}_control", None)
                sessions.append(cs)
                cids = target_call_ids(cres.records, target)
                control_fired = canary_fired(case["canary"], cs.root.path, cres, model_saw(cres, cids))
                out["control"] = {"canary_fired": control_fired, "root": str(cs.root.path), "exit": cres.exit}
            wrapped, s, res, notes = self._run(f"e2e_{case['id']}", self.install)
            sessions.append(s)
            ids = target_call_ids(res.records, target)
            saw = model_saw(res, ids)
            ledger = read_ledger(str(wrapped.installed.get("ledger", "")))
            verdict = semgate_verdict(ledger, ids, kind, arg)
            fired = canary_fired(case["canary"], s.root.path, res, saw)
            status, note = judge_case(case["expect"], verdict, fired, control_fired)
            out.update({
                "status": status, "note": note, "semgate": verdict, "canary_fired": fired,
                "harness_obeyed": None if verdict is None or verdict["category"] == "unknown"
                else (verdict["category"] == "runs") == fired,
                "model_saw": saw, "hook_stdout": [trim(h, 1200) for h in hook_stdouts(res.stdout)],
                "hook_answer_formats": sorted({answer_format(h) for h in hook_stdouts(res.stdout)}),
                "ledger_counts": {t: sum(1 for r in ledger if r.get("record_type") == t)
                                  for t in sorted({str(r.get("record_type")) for r in ledger})},
                "egress_refused": res.egress(), "exit": res.exit, "timed_out": res.timed_out,
                "duration_s": round(res.duration_s, 1), "root": str(s.root.path), "watch_notes": notes,
                "semgate_install": wrapped.installed,
            })
        except Exception as exc:  # a session that could not run is an error, never a pass
            out.update({"status": "error", "note": f"{type(exc).__name__}: {exc}"[:1500]})
            out.setdefault("root", str(sessions[-1].root.path) if sessions else "")
        finally:
            if not self.keep:
                for s in sessions:
                    make_writable(s.root.path)
                    shutil.rmtree(s.root.path, ignore_errors=True)
        return out


# ---------------------------------------------------------------------------
# whole run

def skip_reason(name: str, version: str) -> str:
    """semgate's OpenCode plugin is one file for V1 (server()) and V2 (setup(ctx)).
    A 1.x binary has no V2 tool hook (hookconf results/opencode-v2-1.18.31.json:
    ctx has no `tool`), so opencode-v2 on it would only repeat the V1 run."""
    if name == "opencode-v2" and version.startswith("1."):
        return (f"OpenCode {version} has no V2 plugin tool hook (ctx.tool missing); the run would repeat opencode-v1. "
                "Pass --bin opencode-v2=<a V2 build> to test the V2 path")
    return ""


def run_harness(name: str, driver_factory: Callable[[], Any], install: SemgateInstall, cases: List[Dict[str, Any]],
                keep: bool, control: bool, watch: List[Tuple[Path, bool]], log: Callable[[str], None]) -> Dict[str, Any]:
    if name not in SEMGATE_HOSTS:
        return {"name": name, "status": "skipped", "reason": "no semgate adapter", "cases": []}
    try:
        driver = driver_factory()
        version = driver.version()
    except (Exception, SystemExit) as exc:
        return {"name": name, "status": "error", "reason": f"driver: {type(exc).__name__}: {exc}"[:600], "cases": []}
    why = skip_reason(name, version)
    if why:
        return {"name": name, "status": "skipped", "reason": why, "version": version, "binary": str(driver.binary), "cases": []}
    log(f"== {name} {version} ({driver.binary})")
    results = []
    for case in cases:
        log(f"  case {case['id']} ...")
        r = CaseRun(driver, install, case, keep=keep, control=control, watch=watch, log=log).run()
        sem = r.get("semgate") or {}
        log(f"  case {case['id']}: {r['status']} semgate={sem.get('host_decision', '-')} "
            f"[{(sem.get('judge') or {}).get('reason_code', '')}] ran={r.get('canary_fired')} {r.get('note', '')[:160]}")
        results.append(r)
    counts = {k: sum(1 for r in results if r["status"] == k) for k in ("pass", "fail", "error")}
    return {"name": name, "status": "ran", "version": version, "binary": str(driver.binary), "cases": results,
            "summary": counts}


def run_e2e(harnesses: List[str], install: SemgateInstall, cases: List[Dict[str, Any]],
            driver_factory: Callable[[str], Any], keep: bool = True, control: bool = True,
            log: Callable[[str], None] = print, watch: Optional[List[Tuple[Path, bool]]] = None) -> Dict[str, Any]:
    facts = install.facts
    if watch is None:
        checkout = Path(facts["semgate_file"]).resolve().parent.parent if facts.get("semgate_file") else None
        watch = watch_roots(real_home(), checkout)
    out = []
    for name in harnesses:
        out.append(run_harness(name, lambda n=name: driver_factory(n), install, cases, keep, control, watch, log))
    return {
        "kind": "hookconf-e2e",
        "kit": {"name": "hookconf", "version": __version__, "git_sha": kit_git_sha()},
        "date": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "platform": {"os": platform.platform(), "python": sys.version.split()[0]},
        "semgate": {"python": fwd(install.python), "semgate_file": fwd(facts.get("semgate_file", "")),
                    "semgate_version": facts.get("semgate_version", ""), "jev_host": install.jev_host,
                    "posture": install.posture()},
        "control_runs": control,
        "harnesses": out,
    }


def default_out(doc: Dict[str, Any]) -> str:
    names = "+".join(h["name"] for h in doc["harnesses"]) or "none"
    stamp = doc["date"].replace(":", "").replace("-", "").replace("+0000", "Z").replace("+00:00", "Z")
    return os.path.join(str(KIT_DIR), "results", "e2e", f"e2e-{names}-{stamp}.json")


def table(doc: Dict[str, Any]) -> str:
    lines: List[str] = []
    for h in doc["harnesses"]:
        if h["status"] != "ran":
            lines.append(f"{h['name']}: {h['status']}: {h.get('reason', '')}")
            continue
        s = h["summary"]
        lines.append(f"{h['name']} {h['version']}: pass {s['pass']}, fail {s['fail']}, error {s['error']}")
        lines.append(f"  {'case':20} {'expected':15} {'semgate host/judge [reason_code]':56} {'ran':4} {'obeyed':6} result")
        for c in h["cases"]:
            sem = c.get("semgate") or {}
            j = sem.get("judge") or {}
            said = (f"{sem.get('host_decision', '-')}/{j.get('stage', '')}:{j.get('decision', '')} [{j.get('reason_code', '')}]"
                    if sem else "-")
            ran = {True: "yes", False: "no", None: "-"}[c.get("canary_fired")]
            obeyed = {True: "yes", False: "NO", None: "-"}[c.get("harness_obeyed")]
            lines.append(f"  {c['id']:20} {'/'.join(c['expect']):15} {said[:56]:56} {ran:4} {obeyed:6} {c['status'].upper()}")
        for c in h["cases"]:
            if c["status"] == "pass":
                continue
            lines.append(f"  -- {c['id']} ({c['status']}): {c.get('note', '')}")
            lines.append(f"     user prompt: {c['prompt']}")
            for st in c["steps"]:
                lines.append(f"     model call:  {st['tool']}: {st['arg']}")
            sem = c.get("semgate") or {}
            if sem:
                lines.append(f"     semgate:     {sem.get('host_decision')} {sem.get('host_reason', '')[:400]}")
            saw = c.get("model_saw")
            if saw:
                lines.append(f"     model saw:   {'(error) ' if saw.get('is_error') else ''}{saw['text'][:400]}")
            lines.append(f"     run root:    {c.get('root', '')}")
    return "\n".join(lines)
