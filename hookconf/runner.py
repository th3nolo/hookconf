"""Runs checks for one harness and builds the result document."""
from __future__ import annotations

import datetime as _dt
import os
import platform
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import __version__
from .checks import ALL_IDS, CHECKS, ERROR, NOT_TESTED, NOT_TESTED_NOTES, result
from .levels import compute_levels
from .session import Session, SessionResult

KIT_DIR = Path(__file__).resolve().parent.parent


def kit_git_sha() -> str:
    try:
        git = ["git", "-c", f"safe.directory={KIT_DIR.as_posix()}"]
        sha = subprocess.run(git + ["rev-parse", "--short", "HEAD"], cwd=KIT_DIR, capture_output=True, text=True, timeout=20).stdout.strip()
        dirty = subprocess.run(git + ["status", "--porcelain", "--", "hookconf"], cwd=KIT_DIR, capture_output=True, text=True, timeout=20).stdout.strip()
        return (sha or "unknown") + ("-dirty" if dirty else "")
    except (OSError, subprocess.SubprocessError):
        return "unknown"


class Runner:
    def __init__(self, driver: Any, keep: bool = True, log: Callable[[str], None] = print):
        self.driver = driver
        self.keep = keep
        self.log = log
        self._sessions: Dict[str, SessionResult] = {}
        self._errors: Dict[str, str] = {}
        self._made: List[Session] = []  # every session created, so keep=False can delete the run roots


    def new_session(self, sid: str, **kw: Any) -> Session:
        s = Session(self.driver, sid, keep=self.keep, **kw)
        self._made.append(s)
        return s

    def cleanup(self) -> None:
        """Delete the run roots when keep=False (`run --clean`). Called after all checks read them."""
        for s in self._made:
            s.root.cleanup()

    def session(self, key: str, build: Callable[["Runner"], SessionResult]) -> SessionResult:
        if key in self._errors:
            raise RuntimeError(f"session {key} failed earlier: {self._errors[key]}")
        if key not in self._sessions:
            self.log(f"  session {key} ...")
            try:
                res = build(self)
            except Exception as exc:
                self._errors[key] = f"{type(exc).__name__}: {exc}"
                raise
            self._sessions[key] = res
            self.log(f"  session {key}: exit={res.exit} {res.duration_s:.1f}s probe_events={len(res.probe)} "
                     f"model_requests={len(res.model_requests())} root={res.root}")
        return self._sessions[key]

    def run(self, only: Optional[List[str]] = None) -> Dict[str, Any]:
        try:
            return self._run(only)
        finally:
            self.cleanup()

    def _run(self, only: Optional[List[str]] = None) -> Dict[str, Any]:
        version = self.driver.version()
        wanted = [i for i in ALL_IDS if not only or i in only]
        results: List[Dict[str, Any]] = []
        static = dict(getattr(self.driver, "static_results", {}) or {})
        preflight = getattr(self.driver, "preflight", None)
        gate = preflight(self) if preflight else None  # (status, summary, evidence) applied to every check
        for cid in wanted:
            fn = CHECKS.get(cid)
            if gate and (fn is not None or getattr(self.driver, "gate_all", False)):
                results.append(result(cid, gate[0], gate[1], gate[2], ["preflight"]))
                continue
            if cid in static:
                status, note = static[cid]
                results.append(result(cid, status, note))
                continue
            if fn is None:
                results.append(result(cid, NOT_TESTED, NOT_TESTED_NOTES.get(cid, "not implemented in MVP")))
                continue
            self.log(f"{cid}")
            try:
                r = fn(self)
            except Exception as exc:  # a check crash is an error result, never a pass
                r = result(cid, ERROR, f"check raised {type(exc).__name__}: {exc}",
                           {"traceback": traceback.format_exc()[-3000:]})
            self.log(f"{cid}: {r['status']} - {r['summary'][:200]}")
            results.append(r)
        return {
            "kit": {"name": "hookconf", "version": __version__, "git_sha": kit_git_sha()},
            "harness": {"name": self.driver.name, "version": version, "binary": str(self.driver.binary)},
            "platform": {"os": platform.platform(), "python": sys.version.split()[0]},
            "date": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "only": only or [],
            "results": results,
            "levels": compute_levels(results),
            "sessions": {k: v.summary() for k, v in self._sessions.items()},
            "session_errors": self._errors,
        }

def merge_docs(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Add a partial run (--only) to an existing full result document.

    Same harness name and version only. The ids in `new` replace the old ones;
    each replaced result gets `run` = {kit, date} so the matrix can show where
    it came from. The partial run's sessions and errors go under `updates`,
    so the base run's session summaries are not overwritten. Levels are
    recomputed from the merged results.
    """
    for key in ("name", "version"):
        if old["harness"][key] != new["harness"][key]:
            raise ValueError(f"cannot merge: harness {key} {new['harness'][key]!r} != {old['harness'][key]!r}")
    fresh = {r["id"]: dict(r, run={"kit": new["kit"]["git_sha"], "date": new["date"]}) for r in new["results"]}
    merged = [fresh.pop(r["id"], r) for r in old["results"]] + list(fresh.values())
    order = {rid: i for i, rid in enumerate(ALL_IDS)}
    merged.sort(key=lambda r: order.get(r["id"], len(order)))
    out = dict(old)
    out["results"] = merged
    out["levels"] = compute_levels(merged)
    out["updates"] = list(old.get("updates", [])) + [{
        "only": new.get("only", []), "kit": new["kit"], "date": new["date"], "platform": new["platform"],
        "binary": new["harness"].get("binary"), "sessions": new.get("sessions", {}),
        "session_errors": new.get("session_errors", {})}]
    return out


def kit_errors(doc: Dict[str, Any]) -> List[str]:
    """Things the kit could not measure: `error` results and failed sessions.

    A harness failing a requirement is data (pass/fail/unsupported); an error
    means the measurement itself is missing, which CI treats as a job failure.
    """
    out = [f"{r['id']} error: {r['summary'][:160]}" for r in doc.get("results", []) if r.get("status") == ERROR]
    out += [f"session {k}: {v[:160]}" for k, v in (doc.get("session_errors") or {}).items()]
    return out
