"""python -m oidcfuzz <command>

  analyze POLICY.json [...]   fuzz trust policies (--org --org-id --repo --repo-id set the target)
                              exit 0 clean, 1 breaks the pipeline, 2 over-grants access
  quota                       policy length vs the IAM trust-policy quota
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .analyze import ALLOW_OK, DENY_OK, OUTAGE, OVERREACH, analyze
from .lint import lint
from .scenarios import Target
from . import quota

ICON = {ALLOW_OK: "ok ", DENY_OK: "   ", OVERREACH: "!! ", OUTAGE: "xx "}


def cmd_analyze(paths: list[str], verbose: bool, target: Target) -> int:
    worst = 0
    for p in paths:
        name = pathlib.Path(p).stem
        policy = json.loads(pathlib.Path(p).read_text())
        rep = analyze(name, policy, target)
        over, out = rep.count(OVERREACH), rep.count(OUTAGE)
        print(f"\n== {name}")
        print(f"   accepted-as-intended {rep.count(ALLOW_OK)} | OVERREACH {over} | OUTAGE {out} "
              f"| correctly-denied {rep.count(DENY_OK)}  (of {len(rep.cells)} tokens)")
        print(f"   after migration (target on immutable sub): OVERREACH {rep.count(OVERREACH, 'post')} "
              f"| OUTAGE {rep.count(OUTAGE, 'post')}")
        for f in lint(policy):
            print(f"   lint {f.severity.upper():8} {f.code}: {f.message}")
        if verbose:
            for c in rep.cells:
                if c.state in (OVERREACH, OUTAGE):
                    print(f"   {ICON[c.state]}{c.state:9} {c.sub}")
                    if c.trace:
                        print(f"        {c.trace}")
        worst = max(worst, 2 if over else (1 if out else 0))
    return worst


def cmd_quota() -> int:
    rows = quota.sweep(80)
    for n, length in rows[:: 8]:
        print(f"{n:>3} repos  -> {length:>5} chars")
    print("first repo count over 2,048 (default):", quota.first_over(rows, quota.DEFAULT_LIMIT))
    print("first repo count over 8,192 (max)    :", quota.first_over(rows, quota.MAX_LIMIT))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="oidcfuzz")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze"); a.add_argument("policies", nargs="+"); a.add_argument("-v", "--verbose", action="store_true")
    for flag, typ, dflt in (("--org", str, "acme"), ("--org-id", int, 1001), ("--repo", str, "payments"), ("--repo-id", int, 2002)):
        a.add_argument(flag, type=typ, default=dflt)
    sub.add_parser("quota")
    ns = ap.parse_args(argv)
    return cmd_analyze(ns.policies, ns.verbose, Target(ns.org, ns.org_id, ns.repo, ns.repo_id)) if ns.cmd == "analyze" else cmd_quota()


if __name__ == "__main__":
    sys.exit(main())
