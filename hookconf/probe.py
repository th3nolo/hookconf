"""Recording hook. Standard library only; runs as a plain script:

    python probe.py --event PreToolUse [--log L] [--scenario S] [--format claude|codex|plugin]

Format "plugin" is for in-process hosts: the probe records the event and
prints {"action", "reason", "seconds"}; the host plugin enacts it.

Reads one event JSON on stdin, appends a record to the log (JSONL), and
answers from the scenario rules in the target harness's output format.
Arguments override the environment variables HOOKCONF_LOG,
HOOKCONF_SCENARIO and HOOKCONF_FORMAT.

Scenario file (JSON):
  {"rules": [{"match": {"event": "PreToolUse", "tool": "Bash|Write", "contains": "HK-B1"},
              "respond": "deny", "reason": "HK-DENY-REASON"}],
   "default": "none"}

match keys (all optional, all must hold):
  event     regex, full match on the hook event name (argv --event, else payload)
  tool      regex, full match on tool_name
  contains  substring of the JSON-encoded tool_input
  subagent  true: payload has agent_id; false: it has none

respond values:
  none       no output, exit 0 (no opinion)
  allow | ask | deny | defer     decision JSON in the harness format
  exit2      reason on stderr, exit code 2
  crash      unhandled exception (traceback on stderr, exit 1)
  hang       sleep "seconds" (default 30), then no output
  garbage    invalid JSON on stdout ("{...}" that does not parse), exit 0
  replace    PostToolUse: replace the tool output with "reason"
  perm_allow | perm_deny          PermissionRequest decision

Optional scenario key "transcript_needles": [str]. For every event that
carries a transcript path, the probe reads the file at decision time and
records whether each needle is in it (proves what a hook can read).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

ACTIONS = ("none", "allow", "ask", "deny", "defer", "exit2", "crash", "hang", "garbage", "replace", "perm_allow", "perm_deny", "raw")


def event_name(argv_event: Optional[str], payload: Dict[str, Any]) -> str:
    return argv_event or str(payload.get("hook_event_name") or payload.get("hookEventName") or "")


def matches(match: Dict[str, Any], event: str, payload: Dict[str, Any]) -> bool:
    if "event" in match and not re.fullmatch(str(match["event"]), event):
        return False
    tool = str(payload.get("tool_name") or payload.get("toolName") or "")
    if "tool" in match and not re.fullmatch(str(match["tool"]), tool):
        return False
    if "contains" in match:
        blob = json.dumps(payload.get("tool_input", payload.get("toolArgs", "")))
        if str(match["contains"]) not in blob and json.dumps(str(match["contains"]))[1:-1] not in blob:
            return False
    if "subagent" in match and bool(payload.get("agent_id")) != bool(match["subagent"]):
        return False
    return True


def choose(scenario: Dict[str, Any], event: str, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    for i, rule in enumerate(scenario.get("rules") or []):
        if matches(rule.get("match") or {}, event, payload):
            return i, rule
    return -1, {"respond": scenario.get("default", "none")}


def replacement_like(payload: Optional[Dict[str, Any]], text: str) -> Any:
    """Replacement output with the same shape as the payload's tool_response.

    Claude Code 2.1.280 applies updatedToolOutput for Bash only when it is an
    object shaped like tool_response ({stdout, stderr, ...}); a plain string is
    ignored without any diagnostic (measured, see README).
    """
    original = (payload or {}).get("tool_response")
    if isinstance(original, dict):
        out = dict(original)
        text_keys = [k for k in ("stdout", "output", "content", "result") if isinstance(out.get(k), str)]
        for k in text_keys or ["stdout"]:
            out[k] = text
        if isinstance(out.get("stderr"), str):
            out["stderr"] = ""
        return out
    return text


def render(fmt: str, event: str, action: str, reason: str,
           payload: Optional[Dict[str, Any]] = None) -> Tuple[str, str, int]:
    """(stdout, stderr, exit code) for a non-special action."""
    if action in ("none",):
        return "", "", 0
    if action == "exit2":
        return "", reason, 2
    if action == "garbage":
        # starts with "{" and ends with "}" so harnesses try to parse it as JSON
        return '{"hookSpecificOutput": HOOKCONF-GARBAGE not json}', "", 0
    if action in ("allow", "ask", "deny", "defer"):
        if fmt == "codex" and action == "defer":
            return "", "", 0   # Codex has no defer value; no output means no opinion
        out: Dict[str, Any] = {"hookEventName": event or "PreToolUse", "permissionDecision": action}
        if reason and action != "allow":
            out["permissionDecisionReason"] = reason
        return json.dumps({"hookSpecificOutput": out}), "", 0
    if action in ("perm_allow", "perm_deny"):
        decision: Dict[str, Any] = {"behavior": "allow" if action == "perm_allow" else "deny"}
        if action == "perm_deny":
            decision["message"] = reason
        return json.dumps({"hookSpecificOutput": {"hookEventName": "PermissionRequest", "decision": decision}}), "", 0
    if action == "replace":
        if fmt == "codex":
            # Codex has no output replacement; "block" replaces the result the model sees.
            return json.dumps({"decision": "block", "reason": reason}), "", 0
        return json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                  "updatedToolOutput": replacement_like(payload, reason)}}), "", 0
    raise ValueError(f"unknown action {action!r}")


TRANSCRIPT_KEYS = ("transcript_path", "agent_transcript_path", "transcriptPath")
TRANSCRIPT_MAX = 20 * 1024 * 1024


def transcript_facts(payload: Dict[str, Any], needles: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in TRANSCRIPT_KEYS:
        path = payload.get(key)
        if not isinstance(path, str) or not path:
            continue
        info: Dict[str, Any] = {"path": path, "exists": os.path.isfile(path)}
        if info["exists"]:
            try:
                with open(path, "rb") as fh:
                    data = fh.read(TRANSCRIPT_MAX).decode("utf-8", "replace")
                info["size"] = len(data)
                info["needles"] = {n: (n in data) for n in needles}
            except OSError as exc:
                info["error"] = str(exc)
        out[key] = info
    return out


def _append(log: Optional[str], rec: Dict[str, Any]) -> None:
    if not log:
        return
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="hookconf-probe")
    ap.add_argument("--event")
    ap.add_argument("--log")
    ap.add_argument("--scenario")
    ap.add_argument("--format")
    args = ap.parse_args(argv)
    log = args.log or os.environ.get("HOOKCONF_LOG")
    scenario_path = args.scenario or os.environ.get("HOOKCONF_SCENARIO")
    fmt = args.format or os.environ.get("HOOKCONF_FORMAT") or "claude"

    raw = sys.stdin.buffer.read().decode("utf-8", "replace")
    try:
        payload = json.loads(raw.lstrip("﻿")) if raw.strip() else {}
        parse_error = None
    except ValueError as exc:
        payload, parse_error = {}, str(exc)
    if not isinstance(payload, dict):
        payload = {"_non_object": payload}
    scenario: Dict[str, Any] = {}
    if scenario_path:
        try:
            with open(scenario_path, encoding="utf-8") as fh:
                scenario = json.load(fh)
        except (OSError, ValueError):
            scenario = {}
    event = event_name(args.event, payload)
    idx, rule = choose(scenario, event, payload)
    action = str(rule.get("respond", "none"))
    reason = str(rule.get("reason", "HK-DENY-REASON"))
    rec: Dict[str, Any] = {"ts": time.time(), "pid": os.getpid(), "argv_event": args.event, "event": event,
                           "payload": payload, "rule": idx, "action": action, "format": fmt}
    needles = [str(n) for n in scenario.get("transcript_needles") or []]
    facts = transcript_facts(payload, needles)
    if facts:
        rec["transcript"] = facts
    if parse_error:
        rec["stdin_parse_error"] = parse_error
        rec["stdin_raw"] = raw[:2000]

    if event == "HangEnd":  # plugin format: the plugin reports the end of its own sleep
        _append(log, {"ts": time.time(), "pid": os.getpid(), "event": payload.get("for_event"), "hang_end": True,
                      "tool_use_id": payload.get("tool_use_id")})
        return 0
    if fmt == "plugin":
        # In-process hosts (OpenCode plugins): the plugin enacts the action itself
        # (throw, sleep, set a field), so the probe only records and returns it.
        out = json.dumps({"action": action, "reason": reason, "seconds": float(rule.get("seconds", 30))})
        rec["stdout"], rec["exit"] = out, 0
        _append(log, rec)
        sys.stdout.write(out + "\n")
        return 0
    if action == "crash":
        rec["stdout"], rec["exit"] = "", 1
        _append(log, rec)
        raise RuntimeError("hookconf probe: deliberate crash")
    if action == "hang":
        seconds = float(rule.get("seconds", 30))
        rec["hang_seconds"] = seconds
        _append(log, rec)
        time.sleep(seconds)
        _append(log, {"ts": time.time(), "pid": os.getpid(), "event": event, "hang_end": True,
                      "tool_use_id": payload.get("tool_use_id")})
        return 0
    if action == "raw":  # scenario supplies the exact stdout / exit code (for format experiments)
        out, err, code = str(rule.get("stdout", "")), str(rule.get("stderr", "")), int(rule.get("exit", 0))
    else:
        out, err, code = render(fmt, event, action, reason, payload)
    rec["stdout"], rec["stderr"], rec["exit"] = out, err, code
    _append(log, rec)
    if out:
        sys.stdout.write(out + "\n")
        sys.stdout.flush()
    if err:
        sys.stderr.write(err + "\n")
        sys.stderr.flush()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
