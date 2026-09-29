"""OS-specific path logic (hookconf/binpaths.py) for Linux and Windows,
tested on any OS by passing os_name / machine explicitly."""
import os
from pathlib import Path

import pytest

from hookconf import binpaths as bp
from hookconf import cli
from hookconf.drivers.claude_code import ClaudeCodeDriver
from hookconf.drivers.opencode import OpenCodeDriver
from hookconf.isolation import RunRoot, build_env

LINUX = dict(os_name="posix", machine="x86_64", sys_platform="linux")
WIN = dict(os_name="nt", machine="AMD64", sys_platform="win32")


def rel(paths, prefix):
    return [p.relative_to(prefix).as_posix() for p in paths]


def test_arch_and_os_names():
    assert bp.arch("x86_64") == bp.arch("AMD64") == "x64"
    assert bp.arch("aarch64") == bp.arch("ARM64") == "arm64"
    assert bp.node_os("nt") == "win32"
    assert bp.node_os("posix", "linux") == "linux" and bp.node_os("posix", "darwin") == "darwin"
    assert bp.exe("codex", "nt") == "codex.exe" and bp.exe("codex", "posix") == "codex"


def test_claude_candidates(tmp_path):
    assert rel(bp.candidates("claude-code", tmp_path, **LINUX), tmp_path) == [
        "node_modules/@anthropic-ai/claude-code-linux-x64/claude",
        "node_modules/@anthropic-ai/claude-code-linux-x64-musl/claude"]
    assert rel(bp.candidates("claude-code", tmp_path, **WIN), tmp_path) == [
        "node_modules/@anthropic-ai/claude-code-win32-x64/claude.exe"]


def test_codex_candidates(tmp_path):
    assert rel(bp.candidates("codex", tmp_path, **LINUX), tmp_path)[0] == \
        "node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex"
    assert rel(bp.candidates("codex", tmp_path, **WIN), tmp_path)[0] == \
        "node_modules/@openai/codex-win32-x64/vendor/x86_64-pc-windows-msvc/bin/codex.exe"


def test_opencode_and_pi_candidates(tmp_path):
    lin = rel(bp.candidates("opencode-v1", tmp_path, **LINUX), tmp_path)
    assert lin[0] == "node_modules/opencode-linux-x64/bin/opencode" and "node_modules/opencode-linux-x64-musl/bin/opencode" in lin
    assert rel(bp.candidates("opencode", tmp_path, **WIN), tmp_path)[0] == "node_modules/opencode-windows-x64/bin/opencode.exe"
    assert rel(bp.candidates("pi", tmp_path, **LINUX), tmp_path) == \
        ["node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js"]
    with pytest.raises(KeyError):
        bp.candidates("warp", tmp_path)


def test_resolve_picks_first_existing_and_lists_tried(tmp_path):
    with pytest.raises(FileNotFoundError, match="claude-code-linux-x64"):
        bp.resolve("claude-code", tmp_path, **LINUX)
    musl = tmp_path / "node_modules" / "@anthropic-ai" / "claude-code-linux-x64-musl" / "claude"
    musl.parent.mkdir(parents=True)
    musl.write_bytes(b"")
    assert bp.resolve("claude-code", tmp_path, **LINUX) == musl


def test_windows_batch_shims_are_refused():
    with pytest.raises(ValueError, match="re-parses"):
        bp.check_launchable("C:/npm/claude.cmd", os_name="nt")
    with pytest.raises(ValueError):
        bp.check_launchable("C:/npm/codex.BAT", os_name="nt")
    assert bp.check_launchable("C:/npm/claude.exe", os_name="nt").name == "claude.exe"
    assert bp.check_launchable("/usr/bin/claude.cmd", os_name="posix")  # a name, not a shim, on Linux


def test_git_bash_only_on_windows():
    assert bp.git_bash_env("CLAUDE_CODE_GIT_BASH_PATH", os_name="posix", environ={}) == {}
    assert bp.git_bash_env("X", os_name="nt", environ={}) == {"X": bp.GIT_BASH}
    assert bp.git_bash_env("X", os_name="nt", environ={"X": "D:/git/bash.exe"}) == {"X": "D:/git/bash.exe"}


def test_drivers_set_git_bash_only_on_windows():
    root = RunRoot(keep=False)
    try:
        from types import SimpleNamespace
        session = SimpleNamespace(root=root, mock=SimpleNamespace(url="http://127.0.0.1:9"))
        windows = os.name == "nt"
        assert ("CLAUDE_CODE_GIT_BASH_PATH" in ClaudeCodeDriver("claude").env(session)) == windows
        assert ("OPENCODE_GIT_BASH_PATH" in OpenCodeDriver("opencode").env(session)) == windows
    finally:
        root.cleanup()


def test_drivers_refuse_shims_on_windows(monkeypatch):
    if os.name != "nt":
        pytest.skip("batch shims exist only on Windows")
    with pytest.raises(ValueError):
        ClaudeCodeDriver("C:/npm/claude.cmd")


def test_build_env_posix_keeps_shell_windows_does_not():
    root = RunRoot(keep=False)
    try:
        parent = {"PATH": "p", "SHELL": "/bin/bash", "USER": "u"}
        lin = build_env(root, "http://127.0.0.1:1", parent=parent, os_name="posix")
        win = build_env(root, "http://127.0.0.1:1", parent=parent, os_name="nt")
        assert lin["SHELL"] == "/bin/bash" and lin["USER"] == "u" and "HOMEDRIVE" not in lin
        assert "SHELL" not in win and "USER" not in win and "HOMEDRIVE" in win
    finally:
        root.cleanup()


def test_cli_bin(tmp_path, capsys):
    assert cli.main(["bin", "--harness", "pi", "--prefix", str(tmp_path)]) == 2
    cli_js = tmp_path / "node_modules" / "@earendil-works" / "pi-coding-agent" / "dist" / "bundle" / "cli.js"
    cli_js.parent.mkdir(parents=True)
    cli_js.write_text("", encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["bin", "--harness", "pi", "--prefix", str(tmp_path)]) == 0
    assert capsys.readouterr().out.strip() == str(cli_js)


# Regression, CI run 35906840276: `hookconf bin` printed a relative path
# (ci/npm/claude-code/node_modules/...), the kit starts the harness with
# cwd=<run root>/project, so Linux execve and node (Pi's cli.js, both OSes)
# resolved it against that cwd and did not find it.

def test_relative_paths_become_absolute_bare_names_do_not(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert bp.absolute("ci/npm/codex/codex") == str(tmp_path / "ci" / "npm" / "codex" / "codex")
    assert bp.absolute(os.path.join("a", "b")) == str(tmp_path / "a" / "b")
    assert bp.absolute("claude") == "claude"  # PATH lookup
    assert bp.check_launchable("x/claude").is_absolute()


def test_resolve_with_relative_prefix_returns_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cli_js = tmp_path / "ci" / "npm" / "pi" / "node_modules" / "@earendil-works" / "pi-coding-agent" / "dist" / "bundle" / "cli.js"
    cli_js.parent.mkdir(parents=True)
    cli_js.write_text("", encoding="utf-8")
    got = bp.resolve("pi", "ci/npm/pi")
    assert got.is_absolute() and got == cli_js


def test_drivers_store_absolute_binaries(tmp_path, monkeypatch):
    from hookconf.drivers.codex import CodexDriver
    from hookconf.drivers.pi import PiDriver
    monkeypatch.chdir(tmp_path)
    for drv in (ClaudeCodeDriver("ci/npm/claude-code/claude"), CodexDriver("ci/npm/codex/codex"),
                OpenCodeDriver("ci/npm/opencode/opencode")):
        assert Path(drv.binary).is_absolute(), drv.binary
    monkeypatch.setenv("HOOKCONF_CLAUDE_BIN", "rel/claude")
    assert Path(ClaudeCodeDriver().binary) == tmp_path / "rel" / "claude"
    monkeypatch.setenv("HOOKCONF_PI_CLI", "ci/npm/pi/cli.js")
    pi = PiDriver()
    assert pi.cli == tmp_path / "ci" / "npm" / "pi" / "cli.js"
    from types import SimpleNamespace
    argv = pi.command(SimpleNamespace(), "HKSCRIPT:main go")
    assert Path(argv[1]).is_absolute()  # node gets an absolute script path


def test_missing_binary_is_a_start_error_naming_path_and_cwd():
    from hookconf.runner import Runner
    from test_fake_harness import FakeDriver

    class Missing(FakeDriver):
        def command(self, session, prompt):
            return [os.path.abspath("no-such-dir/no-such-harness"), prompt]
    r = Runner(Missing(), keep=False, log=lambda *_: None).run(["B1"])["results"][0]
    assert r["status"] == "error"
    assert "cannot start" in r["summary"] and "no-such-harness" in r["summary"] and "cwd" in r["summary"]
