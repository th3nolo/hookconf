"""Command line.

    py -m hookconf run --harness claude-code [--only B1,B3] [--out results/x.json] [--bin PATH]
    py -m hookconf report results/*.json --md matrix.md
    py -m hookconf run --harness claude-code --only A2b --merge   # add A2b to the existing result file
    py -m hookconf bin --harness codex --prefix ci/npm/codex        # native binary path (CI)
    py -m hookconf list
    py -m hookconf e2e --harness claude-code --semgate-python PY --semgate-policy POLICY   # local only, see docs/reference.md
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import List, Optional

from .checks import ALL_IDS, CHECKS, NOT_TESTED_NOTES
from .drivers import DRIVERS, get_driver
from .levels import headline
from .report import load, markdown
from .binpaths import BIN_ENV, resolve
from .runner import KIT_DIR, Runner, kit_errors, merge_docs


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="hookconf")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run checks against one harness")
    r.add_argument("--harness", required=True, choices=sorted(DRIVERS))
    r.add_argument("--only", help="comma-separated requirement ids, e.g. B1,B3")
    r.add_argument("--out", help="result JSON path (default results/<harness>-<version>.json)")
    r.add_argument("--bin", help="harness binary path")
    r.add_argument("--clean", action="store_true", help="delete run roots after the run (default: keep for inspection)")
    r.add_argument("--live", action="store_true", help="warp only: show (and, if explicitly enabled, run) the live canary")
    r.add_argument("--merge", action="store_true",
                   help="with --only: replace those ids in the existing result file (same harness version) instead of "
                        "overwriting it; the run is recorded under `updates`")
    r.add_argument("--fail-on-error", action="store_true",
                   help="exit 3 if any result is `error` or a session failed (kit could not measure); "
                        "pass/fail/unsupported results never change the exit code")
    b = sub.add_parser("bin", help="print the native binary of a harness installed in an npm prefix (CI)")
    b.add_argument("--harness", required=True, choices=sorted(BIN_ENV))
    b.add_argument("--prefix", required=True, help="npm prefix dir (holds node_modules)")
    rp = sub.add_parser("report", help="build a markdown matrix from result files")
    rp.add_argument("files", nargs="+")
    rp.add_argument("--md", required=True)
    sub.add_parser("list", help="list requirement ids and whether the MVP tests them")
    e = sub.add_parser("e2e", help="end-to-end: real semgate hook + real Jev against the mock model (local only, "
                                   "needs a TypeSafe key; never in CI)")
    e.add_argument("--harness", action="append", required=True, choices=sorted(DRIVERS),
                   help="repeat for several; harnesses without a semgate adapter are reported as skipped")
    e.add_argument("--semgate-python", required=True, help="interpreter with semgate[typesafe] installed")
    e.add_argument("--semgate-policy", required=True, help="policy file for semgate.json (e.g. policies/router_policy_dev.json)")
    e.add_argument("--case", help="comma-separated case ids (default: all, see hookconf/e2e_cases.py)")
    e.add_argument("--bin", action="append", default=[], metavar="HARNESS=PATH", help="harness binary, e.g. opencode-v2=C:/x/opencode.exe")
    e.add_argument("--block-when-unsure", choices=["on", "off"], default="on",
                   help="semgate enforcement.block_when_unsure (default on, the `semgate init` default)")
    e.add_argument("--no-auto-allow-bash", action="store_true",
                   help="keep bash out of enforcement.auto_allow_tools (the `semgate init` default; then no shell "
                        "command runs without a human approval)")
    e.add_argument("--no-control", action="store_true", help="skip the control session (no hook) per case")
    e.add_argument("--out", help="result JSON (default results/e2e/e2e-<harnesses>-<date>.json)")
    e.add_argument("--clean", action="store_true", help="delete run roots after the run")
    args = ap.parse_args(argv)

    if args.cmd == "e2e":
        return e2e_main(args, ap)

    if args.cmd == "bin":
        try:
            print(resolve(args.harness, args.prefix))
        except (FileNotFoundError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        return 0
    if args.cmd == "list":
        for rid in ALL_IDS:
            print(f"{rid}  {'tested' if rid in CHECKS else 'not tested: ' + NOT_TESTED_NOTES.get(rid, '')}")
        return 0
    if args.cmd == "report":
        files: List[str] = []
        for pattern in args.files:
            files.extend(sorted(glob.glob(pattern)) or [pattern])
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(markdown(load(files)))
        print(f"wrote {args.md} from {len(files)} result file(s)")
        return 0

    driver = get_driver(args.harness, args.bin)
    if args.live:
        if not hasattr(driver, "live_probe"):
            ap.error("--live is only for harnesses without a mock model (warp)")
        from .isolation import RunRoot
        root = RunRoot(prefix=f"hookconf-{driver.name}-live-")
        print(json.dumps(driver.live_probe(str(root.p("project"))), indent=1))
        return 0
    canon = {i.upper(): i for i in ALL_IDS}  # ids are case-insensitive on the command line (A2b)
    only = [canon.get(x.strip().upper(), x.strip()) for x in args.only.split(",")] if args.only else None
    if only:
        unknown = [x for x in only if x not in ALL_IDS]
        if unknown:
            ap.error(f"unknown requirement ids: {unknown}")
    if args.merge and not only:
        ap.error("--merge needs --only (it adds a subset to an existing full result file)")
    doc = Runner(driver, keep=not args.clean).run(only)
    out = args.out or os.path.join(str(KIT_DIR), "results", f"{driver.name}-{doc['harness']['version']}.json")
    if args.merge:
        if not os.path.isfile(out):
            ap.error(f"--merge: {out} does not exist")
        with open(out, encoding="utf-8") as fh:
            doc = merge_docs(json.load(fh), doc)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, ensure_ascii=False)
    print(headline(doc["levels"]))
    for x in doc["results"]:
        print(f"  {x['id']:3} {x['status']:12} {x['summary'][:150]}")
    print(f"wrote {out}")
    errors = kit_errors(doc)
    if args.fail_on_error and errors:
        print("kit errors (--fail-on-error): " + "; ".join(errors), file=sys.stderr)
        return 3
    return 0


def e2e_main(args: argparse.Namespace, ap: argparse.ArgumentParser) -> int:
    from . import e2e, e2e_cases
    why = e2e.refuse_in_ci()
    if why:
        print(why, file=sys.stderr)
        return 2
    bins = {}
    for item in args.bin:
        name, sep, path = item.partition("=")
        if not sep or name not in DRIVERS:
            ap.error(f"--bin wants HARNESS=PATH with a known harness, got {item!r}")
        bins[name] = path
    try:
        cases = e2e_cases.get([c.strip() for c in args.case.split(",")] if args.case else [])
    except KeyError as exc:
        ap.error(str(exc))
    install = e2e.SemgateInstall(args.semgate_python, args.semgate_policy,
                                 block_when_unsure=args.block_when_unsure == "on",
                                 auto_allow_bash=not args.no_auto_allow_bash)
    try:
        facts = install.preflight()
    except e2e.E2EError as exc:
        print(f"e2e preflight: {exc}", file=sys.stderr)
        return 2
    print(f"semgate {facts.get('semgate_version')} from {facts.get('semgate_file')}; Jev host {install.jev_host}; "
          f"posture {json.dumps(install.posture())}")
    harnesses = list(dict.fromkeys(args.harness))
    doc = e2e.run_e2e(harnesses, install, cases, lambda n: get_driver(n, bins.get(n)),
                      keep=not args.clean, control=not args.no_control)
    out = args.out or e2e.default_out(doc)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, ensure_ascii=False)
    print(e2e.table(doc))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
