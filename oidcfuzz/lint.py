"""Static checks on the `sub` / `aud` conditions of a trust policy.

The point of having BOTH a linter and the dynamic fuzzer is cross-checking:
the linter reasons about pattern shape, the fuzzer about what actually
matches. Where they disagree, one of them has a bug (see tests/test_lint.py).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .claims import AUD_KEY, SUB_KEY
from .iam import has_wildcard

CRITICAL, WARN, INFO = "critical", "warn", "info"


@dataclass
class Finding:
    code: str
    severity: str
    message: str
    pattern: str = ""


def _sub_patterns(policy: dict):
    """Yield (operator, pattern, effect) for every Allow-statement sub condition."""
    sts = policy.get("Statement", [])
    sts = sts if isinstance(sts, list) else [sts]
    for st in sts:
        if st.get("Effect") != "Allow":
            continue
        for op, keys in (st.get("Condition") or {}).items():
            for key, val in keys.items():
                if key.lower() == SUB_KEY.lower():
                    for p in (val if isinstance(val, list) else [val]):
                        yield op, p


def _has_key(policy: dict, key: str) -> bool:
    for st in (policy.get("Statement") if isinstance(policy.get("Statement"), list)
               else [policy.get("Statement", {})]):
        for keys in (st.get("Condition") or {}).values():
            if any(k.lower() == key.lower() for k in keys):
                return True
    return False


def _identity_segment(pattern: str) -> str:
    """The part between 'repo:' and the first ':' after it: OWNER/REPO (or with @ids)."""
    body = pattern[len("repo:"):] if pattern.startswith("repo:") else pattern
    return body.split(":", 1)[0]


def lint(policy: dict) -> list[Finding]:
    out: list[Finding] = []
    pats = list(_sub_patterns(policy))

    if not pats:
        out.append(Finding("NO_SUB", CRITICAL,
                           "no condition on the sub claim: any repository on GitHub can present a token"))
    if not _has_key(policy, AUD_KEY):
        out.append(Finding("NO_AUD", WARN,
                           "no condition on aud (GitHub's AWS example pairs aud with sub)"))

    legacy = immutable = False
    for op, p in pats:
        wild = has_wildcard(p) and op == "StringLike"
        seg = _identity_segment(p)
        if op == "StringLike" and not has_wildcard(p):
            out.append(Finding("LIKE_NO_WILDCARD", INFO,
                               "StringLike without a wildcard; StringEquals states the intent", p))
        if wild and re.search(r"[*?]", seg):
            if re.search(r"/\*$", seg):
                out.append(Finding("ORG_WIDE", CRITICAL,
                                   "OWNER/* grants the role to every repository of the owner", p))
            else:
                out.append(Finding("WILDCARD_IN_IDENTITY", CRITICAL,
                                   "wildcard inside OWNER/REPO: it can swallow a longer owner or repo name "
                                   "(acme-labs, payments-sandbox) and even the ':' separator", p))
        elif wild and p.endswith(":*"):
            out.append(Finding("WILDCARD_CONTEXT", WARN,
                               "trailing ':*' accepts every branch, tag, pull_request and environment "
                               "of the repository", p))
        if wild and re.search(r"refs/(heads|tags)/[^:]*\*", p):
            out.append(Finding("WILDCARD_REF", WARN,
                               "wildcard in the ref: anyone who can push a matching branch/tag gets the role", p))
        if "@" in seg:
            immutable = True
        elif p.startswith("repo:"):
            legacy = True

    if pats and legacy and not immutable:
        out.append(Finding("LEGACY_FORMAT_ONLY", WARN,
                           "only matches the legacy sub format; the same repo stops matching after a "
                           "rename/transfer or when the immutable format is enabled (fails closed: outage)"))
    if pats and immutable and not legacy:
        out.append(Finding("IMMUTABLE_FORMAT_ONLY", INFO,
                           "only matches immutable subs; repos still on the legacy format are rejected "
                           "until they opt in, rename or transfer"))
    return out
