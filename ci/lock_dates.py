"""Check that every package in the CI npm lockfiles was published long enough ago.

    py ci/lock_dates.py [--min-hours 72] [--fill-integrity] [ci/npm/*/package-lock.json ...]

For each `node_modules/...` entry in each lockfile it reads the publish time
of that exact version from the npm registry (`time[<version>]` in the full
packument) and prints one line per package. Exit 1 if any version is newer
than --min-hours, or its time cannot be read. Standard library only.

--fill-integrity: some packages ship an npm-shrinkwrap.json without
`integrity` for their own sub-packages (Pi 0.86.1: its five
@earendil-works/* internals), so `npm ci` would not verify those tarballs.
This option copies `dist.integrity` from the registry into those entries,
after checking that the registry tarball URL equals the lock's `resolved`.

Run it after every lockfile change (see docs/reference.md, "CI"). Lockfiles are made
with `npm install --package-lock-only --ignore-scripts --before=<now - 72h>`,
which resolves versions without installing anything.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import json
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

REGISTRY = "https://registry.npmjs.org/"


def entries(lock_path: str) -> List[Tuple[str, str]]:
    """(package name, version) for every installed package in a v2/v3 lockfile."""
    with open(lock_path, encoding="utf-8") as fh:
        lock = json.load(fh)
    out = []
    for key, meta in (lock.get("packages") or {}).items():
        if not key or "version" not in meta:
            continue
        name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]  # aliases carry their real name
        out.append((name, meta["version"]))
    return sorted(set(out))


def packument(name: str) -> Dict:
    url = REGISTRY + urllib.parse.quote(name, safe="@")
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.load(resp)


def fill_integrity(lock_path: str) -> int:
    """Add registry `dist.integrity` to lock entries that have none. Returns the count."""
    with open(lock_path, encoding="utf-8") as fh:
        lock = json.load(fh)
    n = 0
    for key, meta in (lock.get("packages") or {}).items():
        if not key or meta.get("integrity") or "version" not in meta:
            continue
        name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
        dist = packument(name)["versions"][meta["version"]]["dist"]
        if meta.get("resolved") and meta["resolved"] != dist["tarball"]:
            raise SystemExit(f"{key}: lock resolved {meta['resolved']} != registry {dist['tarball']}")
        meta["integrity"] = dist["integrity"]
        print(f"integrity added: {name}@{meta['version']}")
        n += 1
    if n:
        with open(lock_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(lock, indent=2) + "\n")
    return n


def publish_times(name: str) -> Dict[str, str]:
    return packument(name).get("time", {})


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("locks", nargs="*")
    ap.add_argument("--min-hours", type=float, default=72)
    ap.add_argument("--fill-integrity", action="store_true")
    args = ap.parse_args(argv)
    locks = args.locks or sorted(glob.glob("ci/npm/*/package-lock.json"))
    if args.fill_integrity:
        for lock in locks:
            fill_integrity(lock)
    now = dt.datetime.now(dt.timezone.utc)
    pkgs = sorted({e for lock in locks for e in entries(lock)})
    names = sorted({n for n, _ in pkgs})
    with ThreadPoolExecutor(8) as pool:
        times = dict(zip(names, pool.map(publish_times, names)))
    bad = 0
    for name, version in pkgs:
        stamp = times[name].get(version)
        if not stamp:
            print(f"UNKNOWN  {name}@{version}: no publish time in the registry")
            bad += 1
            continue
        age_h = (now - dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))).total_seconds() / 3600
        ok = age_h >= args.min_hours
        bad += not ok
        print(f"{'ok' if ok else 'TOO NEW':8} {name}@{version}  published {stamp}  ({age_h:.0f} h ago)")
    print(f"{len(pkgs)} packages in {len(locks)} lockfile(s); {bad} newer than {args.min_hours:g} h or unknown")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
