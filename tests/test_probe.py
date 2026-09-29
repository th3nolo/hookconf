import json
import subprocess
import sys
from pathlib import Path

import pytest

from hookconf import probe

PROBE = str(Path(probe.__file__))


def run_probe(tmp_path, payload, rules, fmt="claude", event="PreToolUse", extra=None, timeout=30):
    scen = tmp_path / "scenario.json"
    doc = {"rules": rules, "default": "none"}
    doc.update(extra or {})
    scen.write_text(json.dumps(doc), encoding="utf-8")
    log = tmp_path / "log.jsonl"
    proc = subprocess.run([sys.executable, PROBE, "--event", event, "--log", str(log), "--scenario", str(scen), "--format", fmt],
                          input=json.dumps(payload).encode(), capture_output=True, timeout=timeout)
    records = [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
    return proc, records


BASH = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "echo HK-B1 > /tmp/x"},
        "tool_use_id": "t1", "session_id": "s1"}


def test_deny_claude_format(tmp_path):
    proc, recs = run_probe(tmp_path, BASH, [{"match": {"contains": "HK-B1"}, "respond": "deny", "reason": "HK-DENY-REASON"}])
    out = json.loads(proc.stdout)
    assert proc.returncode == 0
    assert out == {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                          "permissionDecisionReason": "HK-DENY-REASON"}}
    assert recs[0]["payload"]["tool_use_id"] == "t1" and recs[0]["action"] == "deny"


def test_no_match_is_no_opinion(tmp_path):
    proc, recs = run_probe(tmp_path, BASH, [{"match": {"tool": "Write"}, "respond": "deny"}])
    assert proc.returncode == 0 and proc.stdout == b""
    assert recs[0]["rule"] == -1 and recs[0]["action"] == "none"


def test_match_keys(tmp_path):
    rules = [{"match": {"event": "Post.*"}, "respond": "deny"},
             {"match": {"subagent": True}, "respond": "ask"},
             {"match": {"tool": "Ba.h", "subagent": False}, "respond": "allow"}]
    _, recs = run_probe(tmp_path, BASH, rules)
    assert recs[0]["rule"] == 2 and recs[0]["action"] == "allow"
    _, recs = run_probe(tmp_path, dict(BASH, agent_id="a1"), rules)
    assert recs[-1]["rule"] == 1


def test_exit2(tmp_path):
    proc, _ = run_probe(tmp_path, BASH, [{"match": {}, "respond": "exit2", "reason": "HK-EXIT2-REASON"}])
    assert proc.returncode == 2 and b"HK-EXIT2-REASON" in proc.stderr and proc.stdout == b""


def test_crash_records_then_fails(tmp_path):
    proc, recs = run_probe(tmp_path, BASH, [{"match": {}, "respond": "crash"}])
    assert proc.returncode == 1 and b"deliberate crash" in proc.stderr
    assert recs[0]["action"] == "crash"


def test_garbage_is_invalid_json_in_braces(tmp_path):
    proc, _ = run_probe(tmp_path, BASH, [{"match": {}, "respond": "garbage"}])
    text = proc.stdout.decode().strip()
    assert text.startswith("{") and text.endswith("}")
    with pytest.raises(ValueError):
        json.loads(text)


def test_hang_records_start_and_end(tmp_path):
    proc, recs = run_probe(tmp_path, BASH, [{"match": {}, "respond": "hang", "seconds": 0.2}])
    assert proc.returncode == 0
    assert recs[0]["hang_seconds"] == 0.2 and recs[1]["hang_end"] is True


def test_codex_defer_is_empty(tmp_path):
    proc, _ = run_probe(tmp_path, BASH, [{"match": {}, "respond": "defer"}], fmt="codex")
    assert proc.stdout == b""


def test_codex_replace_is_block(tmp_path):
    proc, _ = run_probe(tmp_path, BASH, [{"match": {}, "respond": "replace", "reason": "R"}], fmt="codex", event="PostToolUse")
    assert json.loads(proc.stdout) == {"decision": "block", "reason": "R"}


def test_claude_replace_keeps_tool_response_shape(tmp_path):
    payload = dict(BASH, tool_response={"stdout": "ORIG", "stderr": "e", "interrupted": False})
    proc, _ = run_probe(tmp_path, payload, [{"match": {}, "respond": "replace", "reason": "NEW"}], event="PostToolUse")
    out = json.loads(proc.stdout)["hookSpecificOutput"]["updatedToolOutput"]
    assert out == {"stdout": "NEW", "stderr": "", "interrupted": False}


def test_replacement_like_string():
    assert probe.replacement_like({"tool_response": "abc"}, "X") == "X"
    assert probe.replacement_like({}, "X") == "X"


def test_permission_request_allow(tmp_path):
    proc, _ = run_probe(tmp_path, BASH, [{"match": {}, "respond": "perm_allow"}], event="PermissionRequest")
    assert json.loads(proc.stdout)["hookSpecificOutput"]["decision"] == {"behavior": "allow"}


def test_plugin_format_returns_action(tmp_path):
    for action in ("crash", "hang", "deny"):
        proc, recs = run_probe(tmp_path, BASH, [{"match": {}, "respond": action, "seconds": 3}], fmt="plugin")
        assert proc.returncode == 0
        out = json.loads(proc.stdout)
        assert out["action"] == action and out["seconds"] == 3.0
        assert recs[-1]["action"] == action


def test_raw_output(tmp_path):
    proc, _ = run_probe(tmp_path, BASH, [{"match": {}, "respond": "raw", "stdout": "{\"x\": 1}", "exit": 3}])
    assert proc.returncode == 3 and json.loads(proc.stdout) == {"x": 1}


def test_transcript_needles(tmp_path):
    tx = tmp_path / "t.jsonl"
    tx.write_text("hello SECRET-1 world", encoding="utf-8")
    _, recs = run_probe(tmp_path, dict(BASH, transcript_path=str(tx)), [], extra={"transcript_needles": ["SECRET-1", "NOPE"]})
    facts = recs[0]["transcript"]["transcript_path"]
    assert facts["exists"] and facts["needles"] == {"SECRET-1": True, "NOPE": False}


def test_bad_stdin_is_recorded(tmp_path):
    scen = tmp_path / "s.json"
    scen.write_text("{}", encoding="utf-8")
    log = tmp_path / "l.jsonl"
    proc = subprocess.run([sys.executable, PROBE, "--log", str(log), "--scenario", str(scen)], input=b"not json",
                          capture_output=True, timeout=30)
    rec = json.loads(log.read_text(encoding="utf-8"))
    assert proc.returncode == 0 and "stdin_parse_error" in rec and rec["stdin_raw"] == "not json"


def test_render_unknown_action():
    with pytest.raises(ValueError):
        probe.render("claude", "PreToolUse", "bogus", "")
