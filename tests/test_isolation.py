import os
from pathlib import Path

import pytest

from hookconf import isolation as iso
from hookconf.session import real_config_mentions


def test_assert_under(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    assert iso.assert_under(root / "a" / "b.json", root) == Path(os.path.realpath(root / "a" / "b.json"))
    with pytest.raises(iso.IsolationError):
        iso.assert_under(tmp_path / "outside.json", root)
    with pytest.raises(iso.IsolationError):
        iso.assert_under(root / ".." / "escape.json", root)


def test_assert_under_refuses_real_config_even_inside_root(monkeypatch, tmp_path):
    monkeypatch.setattr(iso, "real_home", lambda: tmp_path)
    with pytest.raises(iso.IsolationError):
        iso.assert_under(tmp_path / ".claude" / "settings.json", tmp_path)


def test_check_ancestors(tmp_path):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    with pytest.raises(iso.IsolationError, match="inside the real home"):
        iso.check_ancestors(home / "AppData" / "Temp" / "run", home=home)
    # tmp_path itself sits under the real home on Windows, so use the kit's run base
    base = Path(iso.tempfile.mkdtemp(prefix="hookconf-test-", dir=iso.default_base()))
    try:
        (base / "x").mkdir(parents=True)
        iso.check_ancestors(base / "x", home=home)  # no agent dirs above: fine
        (base / ".codex").mkdir()
        with pytest.raises(iso.IsolationError, match=r"\.codex"):
            iso.check_ancestors(base / "x", home=home)
    finally:
        iso.shutil.rmtree(base, ignore_errors=True)


def test_default_base_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HOOKCONF_RUN_BASE", str(tmp_path / "b"))
    assert iso.default_base() == str(tmp_path / "b") and (tmp_path / "b").is_dir()


def test_default_base_avoids_home(monkeypatch, tmp_path):
    monkeypatch.delenv("HOOKCONF_RUN_BASE", raising=False)
    home = Path(iso.tempfile.gettempdir()).resolve()
    if os.name == "nt":
        base = iso.default_base(home=home)  # temp inside "home": falls back to <SystemDrive>/hookconf-runs
        assert base.lower().endswith("hookconf-runs")
    else:
        with pytest.raises(iso.IsolationError):
            iso.default_base(home=home)


def test_run_root_layout_and_write():
    root = iso.RunRoot(keep=False)
    try:
        for sub in ("home", "appdata", "localappdata", "tmp", "project", "xdg/config"):
            assert root.p(*sub.split("/")).is_dir()
        p = root.write("config/settings.json", "{}")
        assert p.read_text(encoding="utf-8") == "{}"
        with pytest.raises(iso.IsolationError):
            root.write("../escape.txt", "x")
    finally:
        root.cleanup()
    assert not root.path.exists()


def test_build_env_allowlist_and_dummies():
    root = iso.RunRoot(keep=False)
    try:
        parent = {"PATH": "p", "ANTHROPIC_API_KEY": "sk-ant-REAL", "OPENAI_API_KEY": "sk-REAL", "CLAUDECODE": "1",
                  "CLAUDE_CODE_SESSION_ID": "x", "GITHUB_TOKEN": "ghp_real", "RANDOM_VAR": "1"}
        env = iso.build_env(root, "http://127.0.0.1:1", {"CLAUDE_CONFIG_DIR": str(root.p("config"))}, parent=parent)
        assert env["PATH"] == "p"
        assert env["ANTHROPIC_API_KEY"] == iso.DUMMY_KEYS["ANTHROPIC_API_KEY"]
        assert env["OPENAI_API_KEY"] == iso.DUMMY_KEYS["OPENAI_API_KEY"]
        for gone in ("CLAUDECODE", "CLAUDE_CODE_SESSION_ID", "GITHUB_TOKEN", "RANDOM_VAR"):
            assert gone not in env
        for key in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "TEMP"):
            iso.assert_under(env[key], root.path)
        assert env["HTTPS_PROXY"] == "http://127.0.0.1:1" and "127.0.0.1" in env["NO_PROXY"]
    finally:
        root.cleanup()


def test_check_env_rejects_leaks():
    with pytest.raises(iso.IsolationError):
        iso.check_env({"CLAUDECODE": "1"})
    with pytest.raises(iso.IsolationError):
        iso.check_env({"SOME_API_KEY": "real"})
    iso.check_env({"SOME_API_KEY": "sk-hookconf-dummy"})


def test_snapshot_diff(tmp_path):
    (tmp_path / ".claude").mkdir()
    before = iso.snapshot_real_configs(tmp_path)
    (tmp_path / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    diff = iso.diff_snapshots(before, iso.snapshot_real_configs(tmp_path))
    assert list(diff) == [".claude/settings.json"]


def test_real_config_mentions():
    home = str(Path(os.path.expanduser("~")))
    assert real_config_mentions("nothing here") == []
    assert real_config_mentions(f"root {home}{os.sep}.claude{os.sep}agents")
    assert real_config_mentions(home.replace("\\", "/") + "/.agents/skills")
    assert real_config_mentions(home + os.sep + "Desktop" + os.sep + "hookconf") == []
