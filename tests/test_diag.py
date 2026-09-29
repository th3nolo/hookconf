import json

from hookconf.diag import failure_lines
from hookconf.drivers.claude_code import ClaudeCodeDriver
from hookconf.drivers.codex import CodexDriver


def test_kit_strings_are_not_diagnostics():
    # the harness echoing the canary command must not count as a hook-failure report
    line = json.dumps({"type": "assistant", "input": {"command": "echo HK-FAIL-fail_crash > C:/hookconf-runs/hookconf-x-fail_crash/m.txt",
                                                      "description": "hookconf canary"}})
    assert failure_lines(line) == []
    assert failure_lines("PreToolUse hook failed with exit code 1") == ["PreToolUse hook failed with exit code 1"]


def test_claude_hook_response_parsing():
    d = ClaudeCodeDriver("claude")
    ok = {"type": "system", "subtype": "hook_response", "hook_name": "PreToolUse:Bash", "outcome": "success", "exit_code": 0}
    deny = dict(ok, exit_code=2)
    crash = dict(ok, outcome="error", exit_code=1)
    hang = dict(ok, outcome="cancelled", exit_code=1)
    init = {"type": "system", "subtype": "init", "tools": ["hookconf fail error"]}
    out = "\n".join(json.dumps(x) for x in (init, ok, deny, crash, hang))
    diags = d.diagnostics(out, "")
    assert diags == ["hook_response PreToolUse:Bash outcome=error exit_code=1",
                     "hook_response PreToolUse:Bash outcome=cancelled exit_code=1"]


def test_codex_ignores_bypass_notice():
    d = CodexDriver("codex")
    notice = {"type": "item.completed", "item": {"type": "error", "message": "`--dangerously-bypass-hook-trust` is enabled."}}
    real = {"type": "item.completed", "item": {"type": "error", "message": "PreToolUse hook failed"}}
    assert d.diagnostics(json.dumps(notice), "Reading additional input from stdin...") == []
    assert len(d.diagnostics(json.dumps(notice) + "\n" + json.dumps(real), "")) == 1
    assert d.diagnostics("", "WARN hook timed out after 5s") == ["WARN hook timed out after 5s"]
