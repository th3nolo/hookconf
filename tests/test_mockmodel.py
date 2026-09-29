import http.client
import json

from hookconf import mockmodel as mm


def post(mock, path, body):
    conn = http.client.HTTPConnection("127.0.0.1", mock.port, timeout=10)
    conn.request("POST", path, json.dumps(body), {"Content-Type": "application/json"})
    resp = conn.getresponse()
    data = resp.read().decode()
    conn.close()
    return resp.status, data


def sse_events(text):
    out = []
    for block in text.strip().split("\n\n"):
        lines = dict(l.split(": ", 1) for l in block.splitlines() if ": " in l)
        out.append((lines.get("event"), json.loads(lines["data"])))
    return out


def test_script_and_step_anthropic():
    body = {"messages": [{"role": "user", "content": "HKSCRIPT:main go"},
                         {"role": "assistant", "content": [{"type": "tool_use", "id": "a", "name": "Bash", "input": {}}]},
                         {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a", "content": "R1"}]}]}
    assert mm.script_name(body) == "main"
    assert mm.step_index(body) == 1
    assert mm.tool_results(body) == [{"id": "a", "text": "R1", "is_error": False}]


def test_script_and_step_responses():
    body = {"input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "x HKSCRIPT:sub y"}]},
                      {"type": "reasoning"}, {"type": "function_call", "call_id": "c1"},
                      {"type": "function_call_output", "call_id": "c1", "output": "OUT"},
                      {"type": "custom_tool_call", "call_id": "c2"}, {"type": "custom_tool_call_output", "call_id": "c2", "output": "P"}]}
    assert mm.script_name(body) == "sub"
    assert mm.step_index(body) == 2  # two assistant groups
    assert [r["text"] for r in mm.tool_results(body)] == ["OUT", "P"]


def test_tool_result_marker_does_not_select_script():
    body = {"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "a", "content": "HKSCRIPT:evil"}]}]}
    assert mm.script_name(body) is None


def test_anthropic_stream_tool_use():
    plans = {"main": [{"calls": [{"name": "Bash", "input": {"command": "echo hi"}}]}, {"text": "done"}]}
    with mm.MockModel(plans) as mock:
        status, data = post(mock, "/v1/messages", {"model": "m", "stream": True, "tools": [{"name": "Bash"}],
                                                   "messages": [{"role": "user", "content": "HKSCRIPT:main"}]})
        assert status == 200
        evs = sse_events(data)
        names = [e for e, _ in evs]
        assert names[0] == "message_start" and names[-1] == "message_stop"
        start = [d for e, d in evs if e == "content_block_start"][0]["content_block"]
        delta = [d for e, d in evs if e == "content_block_delta"][0]["delta"]
        assert start["type"] == "tool_use" and start["name"] == "Bash"
        assert json.loads(delta["partial_json"]) == {"command": "echo hi"}
        stop = [d for e, d in evs if e == "message_delta"][0]
        assert stop["delta"]["stop_reason"] == "tool_use"
        rec = mock.model_requests("main")[0]
        assert rec["step"] == 0 and rec["response_ids"] == [start["id"]]


def test_anthropic_non_stream_final_and_done():
    plans = {"main": [{"text": "only"}]}
    with mm.MockModel(plans) as mock:
        _, data = post(mock, "/v1/messages", {"tools": [{"name": "x"}], "messages": [{"role": "user", "content": "HKSCRIPT:main"}]})
        assert json.loads(data)["content"] == [{"type": "text", "text": "only"}]
        body = {"tools": [{"name": "x"}], "messages": [{"role": "user", "content": "HKSCRIPT:main"},
                                                        {"role": "assistant", "content": "only"}, {"role": "user", "content": "more"}]}
        _, data = post(mock, "/v1/messages", body)
        assert json.loads(data)["content"][0]["text"] == "HK-DONE"


def test_aux_and_unscripted():
    with mm.MockModel({}) as mock:
        _, data = post(mock, "/v1/messages", {"messages": [{"role": "user", "content": "title please"}]})
        assert json.loads(data)["content"][0]["text"] == mm.AUX_TEXT
        _, data = post(mock, "/v1/messages", {"tools": [{"name": "x"}], "messages": [{"role": "user", "content": "hi"}]})
        assert json.loads(data)["content"][0]["text"] == "HK-NO-SCRIPT"
        assert [r["kind"] for r in mock.records] == ["aux", "unscripted"]


def test_responses_stream_function_and_custom_call():
    plans = {"main": [{"calls": [{"name": "exec_command", "input": {"cmd": "ls"}},
                                 {"name": "apply_patch", "kind": "custom", "input": "*** Begin Patch\n*** End Patch\n"}]}]}
    with mm.MockModel(plans) as mock:
        status, data = post(mock, "/v1/responses", {"model": "m", "tools": [{"type": "function", "name": "exec_command"}],
                                                    "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "HKSCRIPT:main"}]}]})
        assert status == 200
        evs = sse_events(data)
        assert evs[0][0] == "response.created" and evs[-1][0] == "response.completed"
        items = evs[-1][1]["response"]["output"]
        assert [i["type"] for i in items] == ["function_call", "custom_tool_call"]
        assert json.loads(items[0]["arguments"]) == {"cmd": "ls"}
        assert items[1]["input"].startswith("*** Begin Patch")


def test_callable_step_and_before_hook():
    seen = {}

    def step(rec):
        return {"text": f"step saw n={rec['n']}", "before": lambda r: seen.setdefault("before", r["n"])}
    with mm.MockModel({"main": [step]}) as mock:
        _, data = post(mock, "/v1/messages", {"tools": [{"name": "x"}], "messages": [{"role": "user", "content": "HKSCRIPT:main"}]})
        assert json.loads(data)["content"][0]["text"] == "step saw n=1"
        assert seen["before"] == 1
        assert "before" not in mock.records[0]["answer"]


def test_egress_and_unknown_are_recorded(tmp_path):
    log = tmp_path / "mock.jsonl"
    with mm.MockModel({}, log_path=str(log)) as mock:
        conn = http.client.HTTPConnection("127.0.0.1", mock.port, timeout=10)
        conn.request("CONNECT", "api.anthropic.com:443")
        assert conn.getresponse().status == 403
        conn.close()
        status, _ = post(mock, "/v2/whatever", {"a": 1})
        assert status == 404
        conn = http.client.HTTPConnection("127.0.0.1", mock.port, timeout=10)
        conn.request("GET", "/v1/models", headers={"x-api-key": "secret"})
        assert conn.getresponse().status == 200
        conn.close()
    kinds = [json.loads(l)["kind"] for l in log.read_text(encoding="utf-8").splitlines()]
    assert kinds == ["egress", "unknown", "meta"]
    assert "secret" not in log.read_text(encoding="utf-8")
