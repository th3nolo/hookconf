"""A2b (headless ask under bypass mode), merging a partial run into a result
file, and the CI exit rule. Runs against tests/fake_harness.py."""
import json

import pytest

from hookconf import cli
from hookconf.levels import compute_levels
from hookconf.report import markdown
from hookconf.runner import Runner, kit_errors, merge_docs
from test_fake_harness import FakeDriver


class AskDriver(FakeDriver):
    """Fake harness; `ask_runs_in` lists the session modes where it runs the tool on ask."""

    def __init__(self, ask_runs_in=(), reported_mode=None):
        super().__init__()
        self.ask_runs_in = set(ask_runs_in)
        self.reported_mode = reported_mode

    def env(self, session):
        env = super().env(session)
        if session.mode in self.ask_runs_in:
            env["FAKE_ASK_RUNS"] = "1"
        if self.reported_mode and session.mode.startswith("bypass"):
            env["FAKE_PERMISSION_MODE"] = self.reported_mode
        return env


def a2b(driver):
    doc = Runner(driver, keep=False, log=lambda *_: None).run(["A2b"])
    return doc["results"][0]


def test_a2b_pass_when_ask_blocks_in_every_bypass_mode():
    r = a2b(AskDriver())
    assert r["status"] == "pass", r["summary"]
    assert [p["mode"] for p in r["evidence"]["per_mode"]] == ["bypass", "bypass_settings"]
    assert r["sessions"] == ["control_bypass", "ask_bypass", "control_bypass_settings", "ask_bypass_settings"]


def test_a2b_fail_when_one_bypass_mode_runs_the_tool_on_ask():
    r = a2b(AskDriver(ask_runs_in={"bypass_settings"}))
    assert r["status"] == "fail"
    per = {p["mode"]: p for p in r["evidence"]["per_mode"]}
    assert per["bypass"]["status"] == "pass" and per["bypass_settings"]["status"] == "fail"
    assert "shell marker PRESENT" in per["bypass_settings"]["summary"]


def test_a2b_error_when_bypass_mode_is_not_active():
    r = a2b(AskDriver(reported_mode="default"))
    assert r["status"] == "error"
    assert "bypass mode was not active" in r["summary"]
    assert a2b(AskDriver(reported_mode="bypassPermissions"))["status"] == "pass"


def test_a2b_is_core_l2():
    st = {r: "pass" for r in ("O1", "O2", "O3", "O4", "B1", "B2", "B3", "B4", "A2", "A2b", "A3", "A4",
                             "P1", "M1", "M3")}
    st["A2b"] = "fail"
    lv = compute_levels([{"id": i, "status": s} for i, s in st.items()])
    assert lv["core"] == "L1" and lv["per_level"][2]["blocking_status"] == {"A2b": "fail"}
    assert "A2b" not in lv["hardening"]


def doc(results, sha="base", version="1.0", only=None):
    res = [{"id": i, "status": s, "summary": f"{i} {s}", "evidence": {}, "sessions": []} for i, s in results]
    return {"kit": {"git_sha": sha}, "harness": {"name": "h", "version": version, "binary": "b"},
            "platform": {"os": "TestOS"}, "date": f"date-{sha}", "only": only or [], "results": res,
            "levels": compute_levels(res), "sessions": {"s": {"egress_refused": [f"CONNECT {sha}:443"]}},
            "session_errors": {}}


def test_merge_replaces_adds_and_records_the_run():
    old = doc([("B1", "pass"), ("A2", "pass"), ("A3", "fail")])
    new = doc([("A2b", "fail"), ("A3", "pass")], sha="new1", only=["A2b", "A3"])
    m = merge_docs(old, new)
    assert [(r["id"], r["status"]) for r in m["results"]] == [("B1", "pass"), ("A2", "pass"), ("A2b", "fail"), ("A3", "pass")]
    assert m["results"][2]["run"] == {"kit": "new1", "date": "date-new1"} and "run" not in m["results"][0]
    assert m["kit"]["git_sha"] == "base" and m["sessions"] == old["sessions"]
    assert m["updates"][0]["only"] == ["A2b", "A3"] and m["updates"][0]["kit"]["git_sha"] == "new1"
    assert m["levels"] == compute_levels(m["results"])
    md = markdown([m])
    assert "| h | 1.0 | TestOS | base; A2b,A3: new1 | date-base; date-new1 |" in md
    assert "CONNECT base:443" in md and "CONNECT new1:443" in md


def test_merge_refuses_other_version():
    with pytest.raises(ValueError, match="version"):
        merge_docs(doc([("B1", "pass")]), doc([("A2b", "pass")], version="2.0"))


def test_kit_errors_only_for_error_status_and_failed_sessions():
    d = doc([("B1", "fail"), ("A2", "unsupported"), ("A2b", "pass")])
    assert kit_errors(d) == []
    d = doc([("B1", "error")])
    d["session_errors"] = {"observe": "HarnessStartError: no request"}
    assert kit_errors(d) == ["B1 error: B1 error", "session observe: HarnessStartError: no request"]


def test_markdown_adds_os_when_two_columns_share_a_name():
    a, b = doc([("B1", "pass")]), doc([("B1", "pass")])
    b["platform"]["os"] = "Linux-6"
    md = markdown([a, b])
    assert "| h 1.0 (TestOS) | h 1.0 (Linux-6) |" in md


def test_cli_only_ids_are_case_insensitive_and_merge_needs_only(monkeypatch, tmp_path):
    seen = {}

    class FakeRunner:
        def __init__(self, driver, keep=True):
            pass

        def run(self, only):
            seen["only"] = only
            return doc([("A2b", "error")], sha="x")
    monkeypatch.setattr(cli, "Runner", FakeRunner)
    monkeypatch.setattr(cli, "get_driver", lambda name, b: FakeDriver())
    out = tmp_path / "r.json"
    assert cli.main(["run", "--harness", "claude-code", "--only", "a2b", "--out", str(out)]) == 0
    assert seen["only"] == ["A2b"]
    assert cli.main(["run", "--harness", "claude-code", "--only", "A2b", "--out", str(out), "--fail-on-error"]) == 3
    out.write_text(json.dumps(doc([("B1", "pass")], sha="x")), encoding="utf-8")
    assert cli.main(["run", "--harness", "claude-code", "--only", "A2b", "--out", str(out), "--merge"]) == 0
    assert [r["id"] for r in json.loads(out.read_text(encoding="utf-8"))["results"]] == ["B1", "A2b"]
    with pytest.raises(SystemExit):
        cli.main(["run", "--harness", "claude-code", "--merge", "--out", str(out)])
