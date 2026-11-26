"""Run every scenario against a trust policy and classify the outcome.

  ALLOW_OK   token accepted, and the owner wanted it accepted
  DENY_OK    token rejected, and the owner wanted it rejected
  OVERREACH  token accepted but the owner did NOT want it  -> security hole
  OUTAGE     token rejected but the owner wanted it         -> broken pipeline
"""
from __future__ import annotations

from dataclasses import dataclass

from .claims import sub_claim, token_context
from .iam import evaluate_trust_policy
from .scenarios import CONTEXTS, DEFAULT, Target, intended, make_identities

ALLOW_OK, DENY_OK, OVERREACH, OUTAGE = "ALLOW_OK", "DENY_OK", "OVERREACH", "OUTAGE"


@dataclass
class Cell:
    identity: str
    context: str
    sub: str
    accepted: bool
    wanted: bool
    state: str
    trace: str = ""
    legit_fmt: str | None = None  # format of the target repo's own row, else None


@dataclass
class Report:
    name: str
    cells: list[Cell]
    idents: list | None = None

    def _in_phase(self, c: "Cell", phase: str | None) -> bool:
        """Exactly one format is real for the target repo at any moment.
        pre  = repo still on the legacy sub   (drop its immutable row)
        post = repo on the immutable sub      (drop its legacy row)"""
        if phase is None or c.legit_fmt is None:
            return True
        return c.legit_fmt == {"pre": "legacy", "post": "immutable"}[phase]

    def count(self, state: str, phase: str | None = None) -> int:
        return sum(c.state == state and self._in_phase(c, phase) for c in self.cells)

    def of(self, state: str) -> list[Cell]:
        return [c for c in self.cells if c.state == state]

    def grid(self):
        by = {(c.identity, c.context): c for c in self.cells}
        return [[by[(i.label, x.label)] for x in CONTEXTS] for i in self.idents]


def _trace(verdict) -> str:
    hit = verdict.sub_hit()
    if hit is None:
        return ""
    if not hit.captures:
        return f"matched exactly: {hit.pattern}"
    caps = ", ".join(f"*={c!r}" if c else "*=''" for c in hit.captures)
    return f"pattern {hit.pattern}  ->  {caps}"


def analyze(name: str, policy: dict, target: Target = DEFAULT) -> Report:
    cells: list[Cell] = []
    idents = make_identities(target)
    for ident in idents:
        for ctx in CONTEXTS:
            v = evaluate_trust_policy(policy, token_context(ident, ctx))
            wanted = intended(ident, ctx, target)
            if v.allowed and wanted:
                state = ALLOW_OK
            elif v.allowed and not wanted:
                state = OVERREACH
            elif not v.allowed and wanted:
                state = OUTAGE
            else:
                state = DENY_OK
            cells.append(Cell(ident.label, ctx.label, sub_claim(ident, ctx),
                              v.allowed, wanted, state,
                              _trace(v) if v.allowed else "",
                              ident.fmt if ident.role == "legit" else None))
    return Report(name, cells, idents)
