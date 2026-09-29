"""Core level + hardening gaps.

The survey levels (section 3) put hardening items (fail-closed, silent
failures, tamper protection, mid-session reload, schema version) inside
L1/L2/L4. Every harness measured so far fails at least one of them, so every
harness would be "L0" and the real differences (does deny work? does ask
work headless? does PermissionRequest allow work?) disappear. The report
therefore has two parts:

  Core level  L0-L4 from the core requirements only (CORE_LEVELS).
  Hardening   HARDENING ids, listed per harness with their status.

A core level is met when at least one of its requirements is tested, every
tested one passes, and every untested one is in MAY_BE_UNTESTED (they need
an interactive prompt or system policy paths the kit does not write) or has
status not_applicable (an optional product feature the harness does not
have: subagents, bypass mode; never deny/ask/allow or hook input fields). A met level with an untested or not_applicable requirement is
marked "*" (not fully tested). Any other untested core requirement blocks
the level. unsupported (the feature exists but the hook does not see it)
blocks like fail. The reached level is the
highest level with all lower levels met; it carries "*" if any level up to
it has "*".
"""
from __future__ import annotations

from typing import Any, Dict, List

# Survey order, used for the requirement table.
SURVEY_GROUPS = [("L0", "Observe", ["O1", "O2", "O3", "O4"]),
                 ("L1", "Block", ["B1", "B2", "B3", "B4", "B5", "B6"]),
                 ("L2", "Ask + context", ["A1", "A2", "A2b", "A3", "A4", "A5", "A6"]),
                 ("L3", "Allow + remember", ["P1", "P2", "P3", "P4", "P5"]),
                 ("L4", "Content + multi-agent", ["M1", "M2", "M3", "M4", "M5"])]
ALL_IDS = [rid for _, _, ids in SURVEY_GROUPS for rid in ids]

CORE_LEVELS = [("L0", "Observe", ["O1", "O2", "O3", "O4"]),
               ("L1", "Block", ["B1", "B2", "B3", "B4"]),
               ("L2", "Ask + context", ["A1", "A2", "A2b", "A3", "A4"]),
               ("L3", "Allow", ["P1", "P2", "P3"]),
               ("L4", "Content + multi-agent", ["M1", "M3"])]
MAY_BE_UNTESTED = ("A1", "P2", "P3")

HARDENING = ["B5", "B6", "A5", "A6", "P4", "P5", "M2", "M4", "M5"]
GAP_LABEL = {
    "B5": "no fail-closed", "B6": "silent hook failure", "A5": "hook config editable by the agent",
    "A6": "hooks reload mid-session", "P4": "no approve/reject event", "P5": "managed hook can be disabled",
    "M2": "no provenance tags", "M4": "no schema version", "M5": "no persistent transport",
}

BLOCKING = ("fail", "unsupported", "error")
NOT_APPLICABLE = "not_applicable"


def compute_levels(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    status = {r["id"]: r["status"] for r in results}
    per_level = []
    reached, star, chain_ok = "none", False, True
    for lid, name, ids in CORE_LEVELS:
        na = [i for i in ids if status.get(i) == NOT_APPLICABLE]
        tested = [i for i in ids if status.get(i, "not_tested") not in ("not_tested", NOT_APPLICABLE)]
        untested = [i for i in ids if i not in tested and i not in na]
        passed = [i for i in tested if status[i] == "pass"]
        blocking = {i: status[i] for i in tested if status[i] != "pass"}
        blocking.update({i: "not_tested" for i in untested if i not in MAY_BE_UNTESTED})
        met = bool(tested) and not blocking
        level_star = met and bool(untested or na)
        per_level.append({"level": lid, "name": name, "met": met, "star": level_star, "passed": passed,
                          "blocking_status": blocking, "untested": untested, "not_applicable": na})
        if chain_ok and met:
            reached, star = lid, star or level_star
        else:
            chain_ok = False
    hardening = {i: status.get(i, "not_tested") for i in HARDENING}
    gaps = [i for i in HARDENING if hardening[i] in BLOCKING]
    return {"core": reached + ("*" if star and reached != "none" else ""), "reached": reached, "star": star,
            "per_level": per_level, "hardening": hardening, "gaps": gaps,
            "gap_labels": [f"{i} {GAP_LABEL[i]}" for i in gaps],
            "hardening_not_tested": [i for i in HARDENING if hardening[i] == "not_tested"]}


def headline(lv: Dict[str, Any]) -> str:
    """e.g. 'Core L1 · hardening gaps: B6 silent hook failure, A6 hooks reload mid-session'"""
    gaps = ", ".join(lv["gap_labels"]) or "none found"
    return f"Core {lv['core']} · hardening gaps: {gaps}"
