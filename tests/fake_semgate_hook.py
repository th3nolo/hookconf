"""Stand-in for `python -m semgate.claude_hook` in unit tests (no key, no semgate).

    python fake_semgate_hook.py --ledger PATH

Reads one PreToolUse event on stdin. Denies a command that contains BLOCKME,
answers ask for ASKME, allows anything else. Appends one `judgment` and one
`host_response` record to the ledger in semgate's shapes (semgate/ledger.py)
and prints the decision in Claude Code's format.
"""
import argparse
import hashlib
import json
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", required=True)
    args = ap.parse_args()
    event = json.loads(sys.stdin.read() or "{}")
    if event.get("hook_event_name") != "PreToolUse":
        print("{}")
        return 0
    command = str((event.get("tool_input") or {}).get("command", ""))
    if "BLOCKME" in command:
        decision, stage, code = "deny", "hard_rules", "fake_block"
    elif "ASKME" in command:
        decision, stage, code = "ask", "human_gate", "fake_ask"
    else:
        decision, stage, code = "allow", "semantic", "fake_allow"
    digest = hashlib.sha256(json.dumps(event.get("tool_input"), sort_keys=True).encode()).hexdigest()
    reason = f"fake semgate: {stage}/{decision} [{code}]"
    with open(args.ledger, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"record_type": "judgment", "judgment_id": digest,
                             "decision": {"decision": decision, "stage": stage, "reason_code": code, "reasons": [reason]},
                             "envelope": {"action": {"tool": "bash", "arguments": {"command": command}}}}) + "\n")
        fh.write(json.dumps({"record_type": "host_response", "conversation_id": event.get("session_id"),
                             "step_idx": event.get("tool_use_id"), "tool": "bash", "content_digest": digest,
                             "native": {"decision": decision, "reason": reason}}) + "\n")
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
