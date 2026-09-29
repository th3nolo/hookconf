"""End-to-end kit test: Runner + checks against a tiny fake harness
(tests/fake_harness.py) that talks to the mock model and runs the probe.
Proves that B1/B3/B4 pass when the harness enforces and fail when it does not."""
import json
import os
import sys
from pathlib import Path

import pytest

from hookconf.drivers.claude_code import ClaudeCodeDriver
from hookconf.isolation import build_env
from hookconf.runner import Runner

FAKE = str(Path(__file__).with_name("fake_harness.py"))


class FakeDriver(ClaudeCodeDriver):
    name = "fake"
    default_events = ["PreToolUse", "PostToolUse", "UserPromptSubmit"]
    config_env_keys = ["CLAUDE_CONFIG_DIR", "HOME", "USERPROFILE"]
    tool_kinds = ("shell", "write")
    diagnostic_flags = []

    def __init__(self, ignore_deny=False):
        super().__init__(sys.executable)
        self.ignore_deny = ignore_deny

    def version(self):
        return "0.0-fake"

    def env(self, session):
        env = build_env(session.root, session.mock.url, {"CLAUDE_CONFIG_DIR": str(session.root.p("config")),
                                                          "ANTHROPIC_BASE_URL": session.mock.url})
        if self.ignore_deny:
            env["FAKE_IGNORE_DENY"] = "1"
        return env

    def command(self, session, prompt):
        return [sys.executable, FAKE, prompt]


def run(driver, only):
    return {r["id"]: r for r in Runner(driver, keep=False, log=lambda *_: None).run(only)["results"]}


def test_enforcing_harness_passes_block_checks():
    r = run(FakeDriver(), ["B1", "B3", "B4", "O3"])
    assert r["B1"]["status"] == "pass", r["B1"]
    assert r["B3"]["status"] == "pass", r["B3"]
    assert r["B4"]["status"] == "pass", r["B4"]
    assert r["O3"]["status"] == "pass", r["O3"]


def test_non_enforcing_harness_fails():
    r = run(FakeDriver(ignore_deny=True), ["B1", "B3"])
    assert r["B1"]["status"] == "fail"
    assert "PRESENT" in r["B1"]["summary"]
    assert r["B3"]["status"] == "fail"


def test_result_document_shape():
    doc = Runner(FakeDriver(), keep=False, log=lambda *_: None).run(["B1", "A1"])
    assert doc["harness"] == {"name": "fake", "version": "0.0-fake", "binary": sys.executable}
    assert doc["kit"]["git_sha"] and doc["date"] and doc["platform"]["os"]
    ids = [r["id"] for r in doc["results"]]
    assert ids == ["B1", "A1"]
    assert doc["results"][1]["status"] == "not_tested"
    json.dumps(doc)  # serializable


def test_keep_false_deletes_run_roots():
    """`run --clean` (keep=False) removes every run root after the checks read it."""
    rn = Runner(FakeDriver(), keep=False, log=lambda *_: None)
    doc = rn.run(["B1"])
    roots = [s["root"] for s in doc["sessions"].values()]
    assert roots and not any(os.path.exists(r) for r in roots)
    assert doc["results"][0]["status"] == "pass"
    kept = Runner(FakeDriver(), keep=True, log=lambda *_: None)
    doc = kept.run(["O3"])
    roots = [s["root"] for s in doc["sessions"].values()]
    try:
        assert roots and all(os.path.isdir(r) for r in roots)
    finally:
        for s in kept._made:
            s.root.keep = False
            s.root.cleanup()
