"""Run isolation: temp roots, child environment, write guard.

Every harness run gets one temp root. HOME, USERPROFILE, APPDATA,
LOCALAPPDATA, XDG_*, TEMP/TMP and the harness config dir (CLAUDE_CONFIG_DIR,
CODEX_HOME) all point inside it. The child environment is built from an
allowlist, so real API keys and the parent Claude Code session variables
(CLAUDECODE, CLAUDE_CODE_*) never reach the harness. All outbound HTTP(S)
goes through a proxy that points at the mock server, which logs and refuses it.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Dict, Iterable, Optional

# Variables copied from the parent. Everything else is dropped.
ENV_ALLOW = (
    "PATH", "PATHEXT", "SYSTEMROOT", "SystemRoot", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "OS",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER", "NUMBER_OF_PROCESSORS", "ProgramFiles",
    "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles", "ProgramData", "LANG", "LC_ALL", "TERM",
)
# Copied only on Linux/macOS: the harnesses pick their shell tool from SHELL there.
# Not on Windows: a Git Bash parent sets SHELL=/usr/bin/bash, which is not a Windows path.
POSIX_ALLOW = ("SHELL", "USER", "LOGNAME")

DUMMY_KEYS = {
    "ANTHROPIC_API_KEY": "sk-ant-hookconf-dummy-key",
    "OPENAI_API_KEY": "sk-hookconf-dummy-key",
    "HOOKCONF_DUMMY_KEY": "sk-hookconf-dummy-key",
}

# Real config files that must not change during a run (checked by stat only).
REAL_CONFIG_FILES = (
    ".claude/settings.json", ".claude/settings.local.json",
    ".codex/config.toml", ".codex/hooks.json",
    ".gemini/settings.json", ".gemini/config/hooks.json",
)


class IsolationError(RuntimeError):
    pass


def real_home() -> Path:
    return Path(os.path.expanduser("~"))


def assert_under(path: os.PathLike, root: os.PathLike) -> Path:
    """Raise unless `path` resolves inside `root`. Returns the resolved path."""
    p = Path(os.path.realpath(path))
    r = Path(os.path.realpath(root))
    try:
        p.relative_to(r)
    except ValueError:
        raise IsolationError(f"refusing to touch {p}: not under run root {r}")
    home = Path(os.path.realpath(real_home()))
    for name in (".claude", ".codex", ".gemini"):
        real = home / name
        if p == real or real in p.parents:
            raise IsolationError(f"refusing to touch real config {p}")
    return p


def safe_write(path: os.PathLike, text: str, root: os.PathLike) -> Path:
    p = assert_under(path, root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def snapshot_real_configs(home: Optional[Path] = None) -> Dict[str, Optional[tuple]]:
    home = home or real_home()
    out: Dict[str, Optional[tuple]] = {}
    for rel in REAL_CONFIG_FILES:
        p = home / rel
        try:
            st = p.stat()
            out[rel] = (st.st_size, st.st_mtime_ns)
        except OSError:
            out[rel] = None
    return out


def diff_snapshots(before: Dict[str, Optional[tuple]], after: Dict[str, Optional[tuple]]) -> Dict[str, list]:
    return {k: [before.get(k), after.get(k)] for k in set(before) | set(after) if before.get(k) != after.get(k)}


AGENT_CONFIG_DIRS = (".claude", ".codex", ".gemini", ".agents")


def _inside(p: Path, root: Path) -> bool:
    return p == root or root in p.parents


def check_ancestors(path: os.PathLike, home: Optional[Path] = None) -> None:
    """Raise if the run root sits inside the real home, or if any ancestor
    directory holds an agent config dir.

    Measured on Claude Code 2.1.280 (Windows): with the project under
    C:/Users/<user>/AppData/Local/Temp, it loads agents and skills from
    C:/Users/<user>/.claude through the parent-directory walk, even with
    HOME, USERPROFILE and CLAUDE_CONFIG_DIR pointing into the run root.
    """
    p = Path(os.path.realpath(path))
    home = Path(os.path.realpath(home or real_home()))
    if _inside(p, home):
        raise IsolationError(f"run root {p} is inside the real home {home}; harnesses walk parent dirs "
                             f"and would read {home}/.claude. Set HOOKCONF_RUN_BASE to a dir outside it.")
    for anc in [p] + list(p.parents):
        for name in AGENT_CONFIG_DIRS:
            if (anc / name).exists():
                raise IsolationError(f"ancestor {anc} of run root {p} contains {name}; harnesses would load it")


def default_base(home: Optional[Path] = None) -> str:
    """Base dir for run roots: HOOKCONF_RUN_BASE, else the system temp dir if it
    is outside the real home, else (Windows) <SystemDrive>/hookconf-runs."""
    env = os.environ.get("HOOKCONF_RUN_BASE")
    if env:
        base = env
    else:
        tmp = Path(os.path.realpath(tempfile.gettempdir()))
        home_r = Path(os.path.realpath(home or real_home()))
        if not _inside(tmp, home_r):
            base = str(tmp)
        elif os.name == "nt":
            base = os.path.join(os.environ.get("SystemDrive", "C:") + os.sep, "hookconf-runs")
        else:
            raise IsolationError(f"temp dir {tmp} is inside the real home; set HOOKCONF_RUN_BASE")
    os.makedirs(base, exist_ok=True)
    return base


class RunRoot:
    """One temp directory tree per harness run, outside the real home."""

    def __init__(self, base: Optional[str] = None, prefix: str = "hookconf-", keep: bool = True):
        base = base or default_base()
        check_ancestors(base)
        self.path = Path(tempfile.mkdtemp(prefix=prefix, dir=base))
        check_ancestors(self.path)
        self.keep = keep
        for sub in ("home", "appdata", "localappdata", "tmp", "xdg/config", "xdg/data", "xdg/cache", "xdg/state", "project"):
            (self.path / sub).mkdir(parents=True, exist_ok=True)

    def p(self, *parts: str) -> Path:
        return self.path.joinpath(*parts)

    def write(self, rel: str, text: str) -> Path:
        return safe_write(self.p(rel), text, self.path)

    def cleanup(self) -> None:
        if not self.keep:
            shutil.rmtree(self.path, ignore_errors=True)


def build_env(root: RunRoot, proxy_url: str, extra: Optional[Dict[str, str]] = None,
              parent: Optional[Dict[str, str]] = None, allow: Iterable[str] = ENV_ALLOW,
              os_name: Optional[str] = None) -> Dict[str, str]:
    parent = dict(os.environ if parent is None else parent)
    windows = (os_name or os.name) == "nt"
    env: Dict[str, str] = {}
    lower = {k.lower(): k for k in parent}
    for name in list(allow) + ([] if windows else list(POSIX_ALLOW)):
        key = lower.get(name.lower())
        if key is not None:
            env[name] = parent[key]
    home = str(root.p("home"))
    env.update({
        "HOME": home,
        "USERPROFILE": home,
        "APPDATA": str(root.p("appdata")),
        "LOCALAPPDATA": str(root.p("localappdata")),
        "XDG_CONFIG_HOME": str(root.p("xdg", "config")),
        "XDG_DATA_HOME": str(root.p("xdg", "data")),
        "XDG_CACHE_HOME": str(root.p("xdg", "cache")),
        "XDG_STATE_HOME": str(root.p("xdg", "state")),
        "TEMP": str(root.p("tmp")),
        "TMP": str(root.p("tmp")),
        "TMPDIR": str(root.p("tmp")),
        # every outbound request goes to the mock, which records and refuses it
        "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url, "ALL_PROXY": proxy_url,
        "http_proxy": proxy_url, "https_proxy": proxy_url, "all_proxy": proxy_url,
        "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
    })
    if windows:
        drive, rest = os.path.splitdrive(home)
        env["HOMEDRIVE"], env["HOMEPATH"] = drive, rest
    env.update(DUMMY_KEYS)
    if extra:
        env.update(extra)
    check_env(env)
    return env


_FORBIDDEN_PREFIXES = ("CLAUDECODE", "CLAUDE_CODE_SESSION", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_MESSAGING",
                       "CLAUDE_CODE_BRIDGE", "CLAUDE_CODE_CHILD", "CLAUDE_PID", "CLAUDE_PLUGIN", "CODEX_COMPANION",
                       "CLAUDE_CODE_EXECPATH", "CLAUDE_EFFORT")


def check_env(env: Dict[str, str]) -> None:
    for k, v in env.items():
        if k.startswith(_FORBIDDEN_PREFIXES):
            raise IsolationError(f"parent session variable leaked into child env: {k}")
        if k.endswith(("_API_KEY", "_TOKEN", "_KEY")) and k not in DUMMY_KEYS and "hookconf" not in v:
            raise IsolationError(f"non-dummy credential in child env: {k}")
