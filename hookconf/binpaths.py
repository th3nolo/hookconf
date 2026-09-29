"""Where each harness binary lives, per OS, and the Windows-only settings.

The kit was first run only on Windows. This module keeps every OS-specific
path decision in one place, so the drivers stay the same on Linux and
Windows and the logic has unit tests (tests/test_binpaths.py).

npm installs (CI, `npm ci --ignore-scripts`): the wrapper packages put a
placeholder or a Node launcher in `bin/`; the real binary is in a platform
package (an optionalDependency). The kit runs that native binary directly:

  claude-code  node_modules/@anthropic-ai/claude-code-<os>-<arch>/claude[.exe]
               (install.cjs / cli-wrapper.cjs of 2.1.278, PLATFORMS map)
  codex        node_modules/@openai/codex-<os>-<arch>/vendor/<triple>/bin/codex[.exe]
               (bin/codex.js of 0.155.1, findCodexExecutable)
  opencode     node_modules/opencode-<windows|linux|darwin>-<arch>/bin/opencode[.exe]
  pi           node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js (run with node)

Windows `.cmd` / `.bat` shims are refused: Python starts them through
cmd.exe, which re-parses `&`, `|`, `<`, `%` and quotes in the arguments, and
the O3 prompt contains all of them.

Every binary path is made absolute. The kit starts each harness with
cwd=<run root>/project. A relative path such as
`ci/npm/codex/node_modules/.../codex` is then resolved against that cwd on
Linux (execve) and by node for a script argument (Pi's cli.js) on every OS,
so the harness is not found. Measured in the first CI run (35906840276):
all Linux jobs raised FileNotFoundError and Pi failed on both OSes with a
node cjs loader error; the Windows native binaries worked only because
CreateProcess resolves a relative path against the parent's cwd.
"""
from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import Dict, List, Mapping, Optional

GIT_BASH = "C:/Program Files/Git/bin/bash.exe"
SHIM_SUFFIXES = (".cmd", ".bat")


def is_windows(os_name: Optional[str] = None) -> bool:
    return (os_name or os.name) == "nt"


def exe(name: str, os_name: Optional[str] = None) -> str:
    return name + ".exe" if is_windows(os_name) else name


def arch(machine: Optional[str] = None) -> str:
    """Node-style cpu name: x64 or arm64."""
    m = (machine if machine is not None else platform.machine()).lower()
    return {"amd64": "x64", "x86_64": "x64", "x64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(m, m)


def node_os(os_name: Optional[str] = None, sys_platform: Optional[str] = None) -> str:
    """Node-style platform name: win32, linux or darwin."""
    if is_windows(os_name):
        return "win32"
    import sys
    p = sys_platform or sys.platform
    return "darwin" if p == "darwin" else "linux"


def git_bash_env(var: str, os_name: Optional[str] = None, environ: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """{var: path to Git Bash} on Windows, {} elsewhere.

    Claude Code (CLAUDE_CODE_GIT_BASH_PATH) and OpenCode (OPENCODE_GIT_BASH_PATH)
    need Git Bash only on Windows; on Linux and macOS they use the system shell,
    and a Windows path in the variable would be wrong.
    """
    if not is_windows(os_name):
        return {}
    environ = os.environ if environ is None else environ
    return {var: environ.get(var) or GIT_BASH}


def absolute(path: os.PathLike) -> str:
    """Absolute path for anything that names a file by path; a bare name ("claude") is left for PATH lookup."""
    s = os.fspath(path)
    if os.sep in s or "/" in s or (os.altsep and os.altsep in s):
        return os.path.abspath(s)
    return s


def check_launchable(path: os.PathLike, os_name: Optional[str] = None) -> Path:
    """Refuse a Windows batch shim (cmd.exe would re-parse the prompt); make a path absolute."""
    p = Path(absolute(path))
    if is_windows(os_name) and p.suffix.lower() in SHIM_SUFFIXES:
        raise ValueError(f"{p} is a {p.suffix} shim; cmd.exe re-parses & | < % and quotes in the prompt. "
                         f"Point the kit at the native binary (see hookconf/binpaths.py).")
    return p


def candidates(harness: str, prefix: os.PathLike, os_name: Optional[str] = None,
               machine: Optional[str] = None, sys_platform: Optional[str] = None) -> List[Path]:
    """Possible binary paths for `harness` in an npm prefix, best first."""
    nm = Path(prefix) / "node_modules"
    o, a = node_os(os_name, sys_platform), arch(machine)
    if harness == "claude-code":
        keys = [f"{o}-{a}"] + ([f"{o}-{a}-musl"] if o == "linux" else [])
        return [nm / "@anthropic-ai" / f"claude-code-{k}" / exe("claude", os_name) for k in keys]
    if harness == "codex":
        triple = {("linux", "x64"): "x86_64-unknown-linux-musl", ("linux", "arm64"): "aarch64-unknown-linux-musl",
                  ("darwin", "x64"): "x86_64-apple-darwin", ("darwin", "arm64"): "aarch64-apple-darwin",
                  ("win32", "x64"): "x86_64-pc-windows-msvc", ("win32", "arm64"): "aarch64-pc-windows-msvc"}.get((o, a))
        if not triple:
            return []
        return [nm / "@openai" / f"codex-{o}-{a}" / "vendor" / triple / "bin" / exe("codex", os_name),
                nm / "@openai" / "codex" / "vendor" / triple / "bin" / exe("codex", os_name)]
    if harness in ("opencode", "opencode-v1", "opencode-v2"):
        oc = {"win32": "windows"}.get(o, o)
        suffixes = ["", "-baseline"] + (["-musl", "-baseline-musl"] if o == "linux" else [])
        return [nm / f"opencode-{oc}-{a}{s}" / "bin" / exe("opencode", os_name) for s in suffixes]
    if harness == "pi":
        return [nm / "@earendil-works" / "pi-coding-agent" / "dist" / "bundle" / "cli.js"]
    raise KeyError(f"no npm layout known for harness {harness!r}")


def resolve(harness: str, prefix: os.PathLike, os_name: Optional[str] = None,
            machine: Optional[str] = None, sys_platform: Optional[str] = None) -> Path:
    """First existing candidate; FileNotFoundError lists every path tried."""
    tried = candidates(harness, prefix, os_name, machine, sys_platform)
    for p in tried:
        if p.is_file():
            return check_launchable(p, os_name)
    raise FileNotFoundError(f"{harness}: no binary under {prefix}; tried: " + ", ".join(str(p) for p in tried))


# env var the driver reads for each harness (see README.md "Requirements")
BIN_ENV = {"claude-code": "HOOKCONF_CLAUDE_BIN", "codex": "HOOKCONF_CODEX_BIN", "opencode": "HOOKCONF_OPENCODE_BIN",
           "opencode-v1": "HOOKCONF_OPENCODE_BIN", "opencode-v2": "HOOKCONF_OPENCODE_BIN", "pi": "HOOKCONF_PI_CLI"}
