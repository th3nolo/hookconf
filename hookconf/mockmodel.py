"""Local mock model server. Standard library only.

Speaks two wire formats on one port:

  POST /v1/messages          Anthropic Messages (stream and non-stream)
  POST /v1/messages/count_tokens
  POST /v1/responses         OpenAI Responses (SSE stream)
  GET  /v1/models            minimal model list
  CONNECT host:port          proxy sink: logged as an egress attempt, refused

Scripted turn plans
-------------------
A request picks its script from a marker in the user text: "HKSCRIPT:<name>".
The first marker found in user-typed text (not tool results) wins. The step
index is the number of assistant turns already in the request history, so the
server is stateless per request and a harness retry gets the same answer.

A step is a dict:
  {"text": "..."}                                   final answer, end_turn
  {"calls": [{"name": "Bash", "input": {...}}]}      one or more tool calls
      For Responses, add "kind": "custom" for a freeform tool (input is a str).
A step can also be a callable(request_record) -> step dict, and may carry
"before": callable(request_record) that runs before the answer is sent
(used to change files mid-session).

Requests without tools (title generation, quota checks) are "aux" and get a
short text answer. Every request is recorded in memory and in a JSONL file.
"""
from __future__ import annotations

import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional

MARKER = re.compile(r"HKSCRIPT:([A-Za-z0-9_\-]+)")
AUX_TEXT = "HK-AUX"
_REDACT_HEADERS = ("authorization", "x-api-key", "api-key", "cookie")


# ---------------------------------------------------------------------------
# request inspection helpers (pure functions, unit tested)

def _text_parts(content: Any) -> List[str]:
    if isinstance(content, str):
        return [content]
    out: List[str] = []
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and part.get("type") in ("text", "input_text") and isinstance(part.get("text"), str):
                out.append(part["text"])
            elif isinstance(part, str):
                out.append(part)
    return out


def user_texts(body: Dict[str, Any]) -> List[str]:
    """User-typed text blocks in order (Anthropic messages or Responses input)."""
    out: List[str] = []
    if isinstance(body.get("messages"), list):
        for msg in body["messages"]:
            if isinstance(msg, dict) and msg.get("role") == "user":
                out.extend(_text_parts(msg.get("content")))
    items = body.get("input")
    if isinstance(items, str):
        out.append(items)
    elif isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get("role") == "user" and item.get("type", "message") == "message":
                out.extend(_text_parts(item.get("content")))
    return out


def script_name(body: Dict[str, Any]) -> Optional[str]:
    for text in user_texts(body):
        m = MARKER.search(text)
        if m:
            return m.group(1)
    return None


_ASSISTANT_ITEMS = ("function_call", "custom_tool_call", "local_shell_call", "reasoning", "web_search_call", "tool_search_call")


def step_index(body: Dict[str, Any]) -> int:
    """Number of assistant turns already in the history."""
    if isinstance(body.get("messages"), list):
        return sum(1 for m in body["messages"] if isinstance(m, dict) and m.get("role") == "assistant")
    items = body.get("input")
    if not isinstance(items, list):
        return 0
    groups = 0
    in_group = False
    for item in items:
        if not isinstance(item, dict):
            continue
        typ = item.get("type", "message")
        assistant = typ in _ASSISTANT_ITEMS or (typ == "message" and item.get("role") == "assistant")
        if assistant and not in_group:
            groups += 1
        in_group = assistant
    return groups


def tool_names(body: Dict[str, Any]) -> List[str]:
    out = []
    for tool in body.get("tools") or []:
        if isinstance(tool, dict):
            name = tool.get("name") or (tool.get("function") or {}).get("name") or tool.get("type")
            if name:
                out.append(str(name))
    return out


def tool_results(body: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Tool results the harness sent back to the model: [{id, text, is_error}]."""
    out: List[Dict[str, Any]] = []
    if isinstance(body.get("messages"), list):
        for msg in body["messages"]:
            if not (isinstance(msg, dict) and msg.get("role") == "user" and isinstance(msg.get("content"), list)):
                continue
            for part in msg["content"]:
                if isinstance(part, dict) and part.get("type") == "tool_result":
                    content = part.get("content")
                    text = content if isinstance(content, str) else "\n".join(_text_parts(content))
                    out.append({"id": part.get("tool_use_id"), "text": text, "is_error": bool(part.get("is_error"))})
    items = body.get("input")
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get("type") in ("function_call_output", "custom_tool_call_output", "local_shell_call_output", "tool_search_output"):
                output = item.get("output", item.get("tools"))
                text = output if isinstance(output, str) else json.dumps(output)
                out.append({"id": item.get("call_id"), "text": text, "is_error": False})
    return out


# ---------------------------------------------------------------------------
# response builders

def _sse(event: str, data: Dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode("utf-8")


def anthropic_content(step: Dict[str, Any], id_prefix: str) -> List[Dict[str, Any]]:
    if "calls" in step:
        blocks = []
        for i, call in enumerate(step["calls"]):
            blocks.append({"type": "tool_use", "id": f"toolu_{id_prefix}_{i}", "name": call["name"], "input": call.get("input", {})})
        if step.get("text"):
            blocks.insert(0, {"type": "text", "text": step["text"]})
        return blocks
    return [{"type": "text", "text": step.get("text", "done")}]


def anthropic_message(step: Dict[str, Any], model: str, id_prefix: str) -> Dict[str, Any]:
    content = anthropic_content(step, id_prefix)
    stop = "tool_use" if any(b["type"] == "tool_use" for b in content) else "end_turn"
    return {"id": f"msg_{id_prefix}", "type": "message", "role": "assistant", "model": model, "content": content,
            "stop_reason": stop, "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 5, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}}


def anthropic_stream(msg: Dict[str, Any]) -> List[bytes]:
    start = dict(msg, content=[], stop_reason=None)
    start["usage"] = dict(msg["usage"], output_tokens=1)
    chunks = [_sse("message_start", {"type": "message_start", "message": start})]
    for i, block in enumerate(msg["content"]):
        if block["type"] == "text":
            chunks.append(_sse("content_block_start", {"type": "content_block_start", "index": i, "content_block": {"type": "text", "text": ""}}))
            chunks.append(_sse("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {"type": "text_delta", "text": block["text"]}}))
        else:
            chunks.append(_sse("content_block_start", {"type": "content_block_start", "index": i,
                                                       "content_block": {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}}))
            chunks.append(_sse("content_block_delta", {"type": "content_block_delta", "index": i,
                                                       "delta": {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}}))
        chunks.append(_sse("content_block_stop", {"type": "content_block_stop", "index": i}))
    chunks.append(_sse("message_delta", {"type": "message_delta", "delta": {"stop_reason": msg["stop_reason"], "stop_sequence": None},
                                         "usage": {"output_tokens": msg["usage"]["output_tokens"]}}))
    chunks.append(_sse("message_stop", {"type": "message_stop"}))
    return chunks


def responses_items(step: Dict[str, Any], id_prefix: str) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if step.get("text") or "calls" not in step:
        items.append({"type": "message", "id": f"msg_{id_prefix}", "role": "assistant", "status": "completed",
                      "content": [{"type": "output_text", "text": step.get("text", "done"), "annotations": []}]})
    for i, call in enumerate(step.get("calls", [])):
        call_id = f"call_{id_prefix}_{i}"
        if call.get("kind") == "tool_search":
            items.append({"type": "tool_search_call", "id": f"tsc_{id_prefix}_{i}", "call_id": call_id, "status": "completed",
                          "execution": "client", "arguments": call.get("input", {})})
        elif call.get("kind") == "custom":
            items.append({"type": "custom_tool_call", "id": f"ctc_{id_prefix}_{i}", "call_id": call_id, "status": "completed",
                          "name": call["name"], "input": call["input"] if isinstance(call["input"], str) else json.dumps(call["input"])})
        else:
            item = {"type": "function_call", "id": f"fc_{id_prefix}_{i}", "call_id": call_id, "status": "completed",
                    "name": call["name"], "arguments": call["input"] if isinstance(call["input"], str) else json.dumps(call["input"])}
            if call.get("namespace"):
                item["namespace"] = call["namespace"]
            items.append(item)
    return items


def responses_stream(step: Dict[str, Any], model: str, id_prefix: str) -> List[bytes]:
    resp_id = f"resp_{id_prefix}"
    base = {"id": resp_id, "object": "response", "created_at": int(time.time()), "model": model, "output": []}
    items = responses_items(step, id_prefix)
    chunks = [_sse("response.created", {"type": "response.created", "sequence_number": 0, "response": dict(base, status="in_progress")})]
    seq = 1
    for idx, item in enumerate(items):
        chunks.append(_sse("response.output_item.added", {"type": "response.output_item.added", "sequence_number": seq, "output_index": idx, "item": item}))
        seq += 1
        if item["type"] == "message":
            text = item["content"][0]["text"]
            chunks.append(_sse("response.output_text.delta", {"type": "response.output_text.delta", "sequence_number": seq, "item_id": item["id"],
                                                              "output_index": idx, "content_index": 0, "delta": text}))
            seq += 1
        chunks.append(_sse("response.output_item.done", {"type": "response.output_item.done", "sequence_number": seq, "output_index": idx, "item": item}))
        seq += 1
    usage = {"input_tokens": 10, "input_tokens_details": {"cached_tokens": 0}, "output_tokens": 5,
             "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 15}
    chunks.append(_sse("response.completed", {"type": "response.completed", "sequence_number": seq,
                                              "response": dict(base, status="completed", output=items, usage=usage)}))
    return chunks


# ---------------------------------------------------------------------------
# server

class MockModel:
    """Start with .start(); read .url, .records; stop with .stop()."""

    def __init__(self, plans: Optional[Dict[str, List[Any]]] = None, log_path: Optional[str] = None, host: str = "127.0.0.1"):
        self.plans: Dict[str, List[Any]] = dict(plans or {})
        self.log_path = log_path
        self.records: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._n = 0
        self._host = host
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    # -- plan resolution --------------------------------------------------
    def resolve(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Returns {kind, script, step, answer} for a model request body."""
        name = script_name(body)
        idx = step_index(body)
        if not body.get("tools"):
            return {"kind": "aux", "script": name, "step": idx, "answer": {"text": AUX_TEXT}}
        plan = self.plans.get(name or "")
        if plan is None:
            return {"kind": "unscripted", "script": name, "step": idx, "answer": {"text": "HK-NO-SCRIPT"}}
        if idx >= len(plan):
            return {"kind": "main", "script": name, "step": idx, "answer": {"text": "HK-DONE"}}
        return {"kind": "main", "script": name, "step": idx, "answer": plan[idx]}

    def _record(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._n += 1
            rec["n"] = self._n
            rec["ts"] = time.time()
            self.records.append(rec)
            if self.log_path:
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(rec) + "\n")
        return rec

    def model_requests(self, script: Optional[str] = None) -> List[Dict[str, Any]]:
        return [r for r in self.records if r.get("kind") == "main" and (script is None or r.get("script") == script)]

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> "MockModel":
        mock = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:  # silence stderr
                pass

            def _headers(self) -> Dict[str, str]:
                return {k: ("<redacted>" if k.lower() in _REDACT_HEADERS else v) for k, v in self.headers.items()}

            def _send_json(self, code: int, obj: Any) -> None:
                data = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _send_sse(self, chunks: List[bytes]) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                for c in chunks:
                    self.wfile.write(c)
                self.wfile.flush()
                self.close_connection = True

            def _body(self) -> Any:
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n) if n else b""
                if not raw:
                    return {}
                try:
                    return json.loads(raw.decode("utf-8"))
                except ValueError:
                    return {"_raw": raw[:2000].decode("utf-8", "replace")}

            def do_CONNECT(self) -> None:  # proxy sink: real egress attempts end here
                mock._record({"kind": "egress", "method": "CONNECT", "path": self.path, "headers": self._headers()})
                self.send_response(403, "hookconf: egress blocked")
                self.send_header("Content-Length", "0")
                self.end_headers()
                self.close_connection = True

            def do_GET(self) -> None:
                path = self.path.split("?")[0]
                if path.startswith("http://") or path.startswith("https://"):
                    mock._record({"kind": "egress", "method": "GET", "path": self.path, "headers": self._headers()})
                    self._send_json(403, {"error": "hookconf: egress blocked"})
                    return
                if path.rstrip("/").endswith("/models"):
                    mock._record({"kind": "meta", "method": "GET", "path": self.path})
                    self._send_json(200, {"object": "list", "data": [], "models": []})
                    return
                mock._record({"kind": "unknown", "method": "GET", "path": self.path, "headers": self._headers()})
                self._send_json(404, {"error": {"type": "not_found", "message": "hookconf mock: unknown path"}})

            def do_HEAD(self) -> None:
                mock._record({"kind": "unknown", "method": "HEAD", "path": self.path})
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self) -> None:
                body = self._body()
                path = self.path.split("?")[0]
                if path.startswith("http://") or path.startswith("https://"):
                    mock._record({"kind": "egress", "method": "POST", "path": self.path, "headers": self._headers()})
                    self._send_json(403, {"error": "hookconf: egress blocked"})
                    return
                if path.endswith("/count_tokens"):
                    mock._record({"kind": "meta", "method": "POST", "path": self.path})
                    self._send_json(200, {"input_tokens": 100})
                    return
                if path.endswith("/messages"):
                    self._anthropic(body)
                    return
                if path.endswith("/responses"):
                    self._responses(body)
                    return
                mock._record({"kind": "unknown", "method": "POST", "path": self.path, "headers": self._headers(), "body": body})
                self._send_json(404, {"error": {"type": "not_found", "message": "hookconf mock: unknown path"}})

            def _plan(self, body: Dict[str, Any], api: str) -> Dict[str, Any]:
                res = mock.resolve(body)
                answer = res["answer"]
                rec = mock._record({"kind": res["kind"], "api": api, "method": "POST", "path": self.path,
                                    "script": res["script"], "step": res["step"], "headers": self._headers(), "body": body})
                if callable(answer):
                    answer = answer(rec)
                if callable(answer.get("before")):
                    answer["before"](rec)
                rec["answer"] = {k: v for k, v in answer.items() if k != "before"}
                return rec

            def _anthropic(self, body: Dict[str, Any]) -> None:
                rec = self._plan(body, "anthropic")
                prefix = f"hk{rec['n']}_{uuid.uuid4().hex[:6]}"
                msg = anthropic_message(rec["answer"], str(body.get("model", "mock")), prefix)
                rec["response_ids"] = [b["id"] for b in msg["content"] if b["type"] == "tool_use"]
                if body.get("stream"):
                    self._send_sse(anthropic_stream(msg))
                else:
                    self._send_json(200, msg)

            def _responses(self, body: Dict[str, Any]) -> None:
                rec = self._plan(body, "responses")
                prefix = f"hk{rec['n']}_{uuid.uuid4().hex[:6]}"
                rec["response_ids"] = [f"call_{prefix}_{i}" for i in range(len(rec["answer"].get("calls", [])))]
                self._send_sse(responses_stream(rec["answer"], str(body.get("model", "mock")), prefix))

        self._server = ThreadingHTTPServer((self._host, 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    @property
    def port(self) -> int:
        assert self._server is not None
        return self._server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "MockModel":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()
