"""The CI workflow and its pins (stdlib only; no YAML parser needed).

Checks: every action is pinned by a full commit SHA with its tag in a
comment, workflow inputs never appear inside a `run:` script, each harness
has an npm lockfile with one exact top-level version that matches the
workflow header, and the pytest requirements carry hashes.
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WF = ROOT / ".github" / "workflows" / "conformance.yml"
NPM = {"claude-code": "@anthropic-ai/claude-code", "codex": "@openai/codex", "opencode": "opencode-ai",
       "pi": "@earendil-works/pi-coding-agent"}


def text():
    return WF.read_text(encoding="utf-8")


def test_no_tabs_and_top_level_keys():
    t = text()
    assert "\t" not in t
    top = re.findall(r"^([a-z_-]+):", t, re.M)
    assert top == ["name", "on", "permissions", "concurrency", "env", "jobs"]
    jobs = re.findall(r"^  ([a-z_-]+):$", t.split("\njobs:\n", 1)[1], re.M)
    assert jobs == ["unit", "plan", "conformance", "matrix"]


def test_actions_pinned_by_sha_and_listed_in_header():
    t = text()
    uses = re.findall(r"uses: ([\w./-]+)@(\S+) # (v[\d.]+)", t)
    assert uses and len(uses) == t.count("uses: ")
    for action, ref, tag in uses:
        assert re.fullmatch(r"[0-9a-f]{40}", ref), (action, ref)
        assert re.search(rf"#   {re.escape(action)} +{re.escape(tag)} +{ref}", t), f"{action} missing from header"


def test_inputs_only_through_env():
    """`${{ inputs.* }}` inside a run script would allow script injection."""
    for block in re.findall(r"run: \|\n((?:          .*\n|\n)+)", text()):
        assert "inputs." not in block and "github.event" not in block


def test_npm_lockfiles_match_header():
    t = text()
    for d, pkg in NPM.items():
        base = ROOT / "ci" / "npm" / d
        deps = json.loads((base / "package.json").read_text(encoding="utf-8"))["dependencies"]
        assert list(deps) == [pkg]
        version = deps[pkg]
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), "exact version, no range"
        lock = json.loads((base / "package-lock.json").read_text(encoding="utf-8"))
        assert lock["packages"][f"node_modules/{pkg}"]["version"] == version
        assert all(m.get("integrity") for k, m in lock["packages"].items() if k), f"{d}: entry without integrity"
        assert re.search(rf"#     {re.escape(pkg)} +{re.escape(version)} +npm ", t), f"{pkg}@{version} not in header"


def test_python_and_node_pins():
    t = text()
    assert re.search(r'PYTHON_VERSION: "\d+\.\d+\.\d+"', t) and re.search(r'NODE_VERSION: "\d+\.\d+\.\d+"', t)
    req = (ROOT / "ci" / "requirements-ci.txt").read_text(encoding="utf-8")
    pins = re.findall(r"^([a-z]+)==([\d.]+)", req, re.M)
    assert {p for p, _ in pins} == {"pytest", "iniconfig", "packaging", "pluggy", "pygments", "colorama"}
    assert req.count("--hash=sha256:") == len(pins)
    assert ("pytest", "9.1.1") in pins
