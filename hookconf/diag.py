"""Find hook-failure diagnostics in harness output."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List

# The kit's own strings contain "hookconf" and "fail" (paths, markers, probe
# traceback). Remove them before matching, so a harness echoing the tool
# command is not mistaken for a diagnostic.
KIT_WORDS = re.compile(r"hookconf[\w.:/\-]*|HK-[\w-]+", re.I)
FAIL_WORDS = ("error", "fail", "timed out", "timeout", "cancel", "invalid", "exit code", "exit status")


def failure_lines(text: str, words: Iterable[str] = FAIL_WORDS) -> List[str]:
    """Plain-text lines that mention a hook and a failure word."""
    out = []
    for line in text.splitlines():
        low = KIT_WORDS.sub("", line).lower()
        if "hook" in low and any(w in low for w in words):
            out.append(line[:600])
    return out


def json_lines(text: str) -> List[Dict[str, Any]]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
    return out


def non_json_text(text: str) -> str:
    return "\n".join(l for l in text.splitlines() if not l.strip().startswith("{"))
