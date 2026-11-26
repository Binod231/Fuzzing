"""The universe of tokens we throw at a trust policy, and what the owner intended.

Intent (the same for every policy under test, so results are comparable):
    "Only the release pipeline of OWNER/REPO may assume this role:
     pushes to main, and jobs that target the `prod` environment.
     Nothing else - no other branch, tag, PR, repo or org."

The target repo may present itself in either subject format, because the same
repo flips from legacy to immutable when it is renamed, transferred or opts in.
"""
from __future__ import annotations

from dataclasses import dataclass

from .claims import Context, Identity


@dataclass(frozen=True)
class Target:
    org: str = "acme"
    org_id: int = 1001
    repo: str = "payments"
    repo_id: int = 2002


DEFAULT = Target()


def make_identities(t: Target = DEFAULT) -> list[Identity]:
    o, r = t.org, t.repo
    return [
        Identity(o, t.org_id, r, t.repo_id, "legacy", f"{o}/{r} (legacy sub)", "legit"),
        Identity(o, t.org_id, r, t.repo_id, "immutable", f"{o}/{r} (immutable sub)", "legit"),
        Identity(o, t.org_id, f"{r}-sandbox", 2003, "legacy", f"{o}/{r}-sandbox", "other"),
        Identity(o, t.org_id, "marketing-site", 2004, "legacy", f"{o}/marketing-site", "other"),
        Identity(f"{o}-labs", 3001, r, 3002, "legacy", f"{o}-labs/{r}", "attacker"),
        Identity("mallory", 4001, r, 4002, "legacy", f"mallory/{r}", "attacker"),
        # a stranger already holds the trusted name in legacy format (name freed and
        # re-registered before the immutable default existed: a dangling trust)
        Identity(o, 9001, r, 9002, "legacy", f"stranger holds {o}/{r} (legacy)", "attacker"),
        # the name re-registered after 2026-07-15: GitHub issues an immutable sub with the NEW ids
        Identity(o, 9001, r, 9002, "immutable", f"re-registered {o}/{r} (post-cutoff)", "attacker"),
    ]


IDENTITIES: list[Identity] = make_identities(DEFAULT)

CONTEXTS: list[Context] = [
    Context("branch", "main"),
    Context("branch", "feature/login"),
    Context("tag", "v1.2.0"),
    Context("pull_request"),
    Context("environment", "prod"),
    Context("environment", "prod-debug"),
]


def intended(identity: Identity, ctx: Context, t: Target = DEFAULT) -> bool:
    if not (identity.owner == t.org and identity.repo == t.repo
            and identity.owner_id == t.org_id and identity.repo_id == t.repo_id):
        return False
    return (ctx.kind == "branch" and ctx.value == "main") or (
        ctx.kind == "environment" and ctx.value == "prod")
