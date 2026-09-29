"""Driver config writers and static drivers (no harness process is started)."""
import json
import os
from types import SimpleNamespace

import pytest

from hookconf.drivers import DRIVERS, get_driver
from hookconf.drivers.claude_code import ClaudeCodeDriver
from hookconf.drivers.codex import CodexDriver
from hookconf.drivers.opencode import OpenCodeDriver, OpenCodeV2Driver
from hookconf.drivers.pi import PiDriver
from hookconf.drivers.warp import WarpDriver
from hookconf.isolation import assert_under
from hookconf.runner import Runner
from hookconf.session import Session


@pytest.fixture
def session_for():
    made = []

    def make(driver, mode="default"):
        s = Session(driver, "unit", mode=mode, keep=False)
        s.mock = SimpleNamespace(url="http://127.0.0.1:9")
        made.append(s)
        return s
    yield make
    for s in made:
        s.root.cleanup()


def test_registry():
    assert set(DRIVERS) == {"claude-code", "codex", "opencode-v1", "opencode-v2", "warp", "pi"}
    with pytest.raises(SystemExit):
        get_driver("nope")


def test_claude_config_and_env(session_for):
    d = ClaudeCodeDriver("claude")
    s = session_for(d)
    path = d.write_config(s)
    assert_under(path, s.root.path)
    cfg = json.loads(path.read_text(encoding="utf-8"))
    assert set(cfg["hooks"]) == set(d.default_events)
    cmd = cfg["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "--event PreToolUse" in cmd and "--format claude" in cmd
    env = d.env(s)
    assert env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:9"
    for key in d.config_env_keys:
        assert_under(env[key], s.root.path)
    assert d.command(session_for(d, "bypass"), "x")[-1] == "--dangerously-skip-permissions"
    assert "defaultMode" not in cfg["permissions"]


def test_claude_bypass_settings_mode(session_for):
    d = ClaudeCodeDriver("claude")
    s = session_for(d, "bypass_settings")
    cfg = json.loads(d.write_config(s).read_text(encoding="utf-8"))
    assert cfg["permissions"]["defaultMode"] == "bypassPermissions"
    assert "--dangerously-skip-permissions" not in d.command(s, "x")  # settings only, no flag
    assert [m for m, _ in d.bypass_modes] == ["bypass", "bypass_settings"]
    out = "\n".join([json.dumps({"type": "system", "subtype": "init", "permissionMode": "bypassPermissions"}),
                     "not json", json.dumps({"type": "result", "permission_denials": [{"tool_name": "Bash"}]})])
    seen = d.mode_evidence(out)
    assert seen == {"permissionMode": "bypassPermissions", "permission_denials": [{"tool_name": "Bash"}]}
    assert d.bypass_active(seen) is True
    assert d.bypass_active({"permissionMode": "default"}) is False
    assert d.bypass_active(d.mode_evidence("")) is None  # unknown: no init record


def test_codex_config(session_for):
    d = CodexDriver("codex")
    s = session_for(d)
    hooks = json.loads(d.write_config(s).read_text(encoding="utf-8"))
    h = hooks["hooks"]["PreToolUse"][0]["hooks"][0]
    assert h["commandWindows"].startswith("& ") and h["commandWindows"].endswith("; exit $LASTEXITCODE")
    toml = s.root.p("codex", "config.toml").read_text(encoding="utf-8")
    assert 'base_url = "http://127.0.0.1:9/v1"' in toml and 'wire_api = "responses"' in toml
    assert "include_instructions = false" in toml
    assert d.command(session_for(d, "strict"), "P")[-2:] == ["--approve-for-me", "P"]
    assert "-s" not in d.command(session_for(d, "strict"), "P")


def test_opencode_plugin_and_config(session_for):
    d = OpenCodeDriver("opencode")
    s = session_for(d)
    plugin = d.write_config(s).read_text(encoding="utf-8")
    assert "__HOOKCONF_" not in plugin
    assert 'const VARIANT = "v1"' in plugin and "const ENABLED = true" in plugin
    cfg = json.loads(s.root.p("xdg", "config", "opencode", "opencode.json").read_text(encoding="utf-8"))
    assert cfg["provider"]["hookconf"]["options"]["baseURL"] == "http://127.0.0.1:9/v1"
    assert cfg["permission"]["bash"] == "allow"
    assert "const ENABLED = false" in d.remove_hooks(s).read_text(encoding="utf-8")
    strict = session_for(d, "strict")
    assert d.opencode_json(strict)["permission"]["bash"] == "ask"
    argv = d.command(session_for(d, "bypass"), 'HKSCRIPT:main a "b" c')
    assert "--auto" in argv and argv[-4:] == ["HKSCRIPT:main", "a", '"b"', "c"]
    env = d.env(s)
    assert env["OPENCODE_DISABLE_CLAUDE_CODE"] == "1"
    for key in d.config_env_keys:
        assert_under(env[key], s.root.path)
    v2 = OpenCodeV2Driver("opencode")
    assert 'const VARIANT = "v2"' in v2.plugin_source(session_for(v2))
    # no ask value in the tool hook: A2 and A2b are gaps (unsupported), never n/a
    for drv in (d, v2):
        assert drv.static_results["A2"][0] == drv.static_results["A2b"][0] == "unsupported"


def fake_warp(tmp_path, content):
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "oz.cmd").write_text('set "WARP_CLI_MODE=1"', encoding="utf-8")
    exe = tmp_path / ("warp.exe" if os.name == "nt" else "warp")
    exe.write_bytes(content)
    return WarpDriver(str(exe))


def test_warp_static(tmp_path, monkeypatch):
    d = fake_warp(tmp_path, b"xx v0.2026.09.16.08.27.stable_02 yy command_denylist command_allowlist v0.2026.09.16.08.27.stable_02")
    monkeypatch.setattr(WarpDriver, "binary", d.binary, raising=False)
    assert d.version() == "v0.2026.09.16.08.27.stable_02"
    doc = Runner(d, keep=False, log=lambda *_: None).run()
    assert {r["status"] for r in doc["results"]} == {"unsupported"}
    ev = doc["results"][0]["evidence"]
    assert ev["hook_strings_in_binary"]["PreToolUse"] == 0
    assert ev["permission_fields_in_binary"]["command_denylist"] == 1
    assert "oz.cmd" in ev["shims"]


def test_warp_live_refuses_without_consent(tmp_path, monkeypatch):
    monkeypatch.delenv("HOOKCONF_WARP_LIVE_ACCEPT", raising=False)
    d = fake_warp(tmp_path, b"")
    plan = d.live_probe(str(tmp_path / "project"))
    assert plan["status"].startswith("refused")
    assert plan["argv"][1:3] == ["agent", "run"]
    assert "exit" not in plan


def test_pi_config(session_for):
    d = PiDriver("C:/x/dist/bundle/cli.js")
    s = session_for(d)
    ext = d.write_config(s).read_text(encoding="utf-8")
    assert "__HOOKCONF_" not in ext and "const ENABLED = true" in ext
    models = json.loads(s.root.p("pi-agent", "models.json").read_text(encoding="utf-8"))
    prov = models["providers"]["hookconf"]
    assert prov["api"] == "anthropic-messages" and prov["baseUrl"] == "http://127.0.0.1:9"
    assert "const ENABLED = false" in d.remove_hooks(s).read_text(encoding="utf-8")
    env = d.env(s)
    assert env["PI_OFFLINE"] == "1"
    for key in d.config_env_keys:
        assert_under(env[key], s.root.path)
    argv = d.command(s, "HKSCRIPT:main go")
    assert argv[-1] == "HKSCRIPT:main go" and "--mode" in argv
    assert set(d.static_results) == {"O4", "M3", "P1"}
    assert d.static_results["O4"][0] == d.static_results["M3"][0] == "not_applicable"
    assert d.static_results["P1"][0] == "unsupported"  # missing allow capability is a gap, not n/a
