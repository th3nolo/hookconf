"""A tiny stand-in agent harness for kit tests (no real harness needed).

It speaks the Anthropic Messages API to ANTHROPIC_BASE_URL (the mock),
runs command hooks from $CLAUDE_CONFIG_DIR/settings.json in the Claude Code
format, and executes two tools itself:
  Bash   only "echo TEXT > PATH" (writes TEXT to PATH)
  Write  {file_path, content}

FAKE_IGNORE_DENY=1 makes it ignore deny answers (a broken harness), so tests
can prove that a check fails when the harness does not enforce.
FAKE_ASK_RUNS=1 makes it run the tool on an "ask" answer (what a harness that
auto-approves ask in bypass mode would do). FAKE_PERMISSION_MODE=<mode> makes
it print a stream-json init record with that permissionMode.
"""
import json
import os
import re
import subprocess
import sys
import urllib.request
import uuid


def hooks(event):
    path = os.path.join(os.environ["CLAUDE_CONFIG_DIR"], "settings.json")
    with open(path, encoding="utf-8") as fh:
        settings = json.load(fh)
    return [h["command"] for group in settings.get("hooks", {}).get(event, []) for h in group["hooks"]]


def run_hooks(event, payload):
    """Returns (decision, reason). decision: None | "deny" | "ask"."""
    for cmd in hooks(event):
        proc = subprocess.run(cmd, shell=True, input=json.dumps(payload).encode(), capture_output=True, timeout=60)
        if proc.returncode == 2:
            return "deny", proc.stderr.decode().strip()
        out = proc.stdout.decode().strip()
        if out.startswith("{"):
            try:
                spec = json.loads(out).get("hookSpecificOutput", {})
            except ValueError:
                continue
            if spec.get("permissionDecision") in ("deny", "ask"):
                return spec["permissionDecision"], spec.get("permissionDecisionReason", "")
    return None, ""


def call_model(messages):
    body = {"model": "fake", "max_tokens": 100, "tools": [{"name": "Bash"}, {"name": "Write"}], "messages": messages}
    req = urllib.request.Request(os.environ["ANTHROPIC_BASE_URL"] + "/v1/messages", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def execute(name, args):
    if name == "Bash":
        m = re.fullmatch(r"echo (.*?) > (\S+)", args["command"].strip())
        if not m:
            return args["command"].replace("echo ", "", 1)
        with open(m.group(2), "w", encoding="utf-8") as fh:
            fh.write(m.group(1) + "\n")
        return ""
    if name == "Write":
        with open(args["file_path"], "w", encoding="utf-8") as fh:
            fh.write(args["content"])
        return "written"
    return f"unknown tool {name}"


def main():
    prompt = sys.argv[1]
    session = str(uuid.uuid4())
    if os.environ.get("FAKE_PERMISSION_MODE"):
        print(json.dumps({"type": "system", "subtype": "init", "permissionMode": os.environ["FAKE_PERMISSION_MODE"]}))
    base = {"session_id": session, "cwd": os.getcwd(), "prompt_id": str(uuid.uuid4())}
    run_hooks("UserPromptSubmit", dict(base, hook_event_name="UserPromptSubmit", prompt=prompt))
    messages = [{"role": "user", "content": [{"type": "text", "text": prompt}]}]
    for _ in range(10):
        msg = call_model(messages)
        messages.append({"role": "assistant", "content": msg["content"]})
        uses = [b for b in msg["content"] if b["type"] == "tool_use"]
        if not uses:
            print(json.dumps({"type": "result", "text": msg["content"][0].get("text")}))
            return 0
        results = []
        for use in uses:
            ev = dict(base, hook_event_name="PreToolUse", tool_name=use["name"], tool_input=use["input"], tool_use_id=use["id"])
            decision, reason = run_hooks("PreToolUse", ev)
            ask_runs = decision == "ask" and os.environ.get("FAKE_ASK_RUNS")
            if decision and not os.environ.get("FAKE_IGNORE_DENY") and not ask_runs:
                results.append({"type": "tool_result", "tool_use_id": use["id"], "content": reason, "is_error": True})
                continue
            out = execute(use["name"], use["input"])
            run_hooks("PostToolUse", dict(ev, hook_event_name="PostToolUse", tool_response=out))
            results.append({"type": "tool_result", "tool_use_id": use["id"], "content": out})
        messages.append({"role": "user", "content": results})
    return 1


if __name__ == "__main__":
    sys.exit(main())
