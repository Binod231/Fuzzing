"""A small, honest model of how IAM evaluates trust-policy conditions.

Scope (deliberately narrow):
  * operators: StringEquals, StringNotEquals, StringLike, StringNotLike,
    StringEqualsIgnoreCase
  * several values for one key  -> OR
  * several keys / operators    -> AND
  * StringLike wildcards: `*` (any run of characters, including ':' and '/')
    and `?` (exactly one character); matching is case-sensitive
  * `${*}`, `${?}`, `${$}` are the IAM escapes for a literal * ? $

It does NOT model policy variables, Principal checks, SCPs, permission
boundaries or session policies. It evaluates only the Condition block, which
is where GitHub-OIDC trust policies succeed or fail.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

POSITIVE_OPS = {"StringEquals", "StringLike", "StringEqualsIgnoreCase"}
NEGATED_OPS = {"StringNotEquals", "StringNotLike"}
SUPPORTED_OPS = POSITIVE_OPS | NEGATED_OPS

_ESCAPES = {"${*}": "*", "${?}": "?", "${$}": "$"}
_TOKEN = re.compile(r"\$\{[*?$]\}|\*|\?|[^*?$]+|\$")


def compile_like(pattern: str) -> re.Pattern[str]:
    """Translate an IAM StringLike pattern to a regex.

    Every wildcard becomes a capture group so a verdict can show exactly which
    text each `*` or `?` swallowed (see Match.captures).
    """
    out: list[str] = []
    for tok in _TOKEN.findall(pattern):
        if tok in _ESCAPES:
            out.append(re.escape(_ESCAPES[tok]))
        elif tok == "*":
            out.append("(.*)")
        elif tok == "?":
            out.append("(.)")
        else:
            out.append(re.escape(tok))
    return re.compile("".join(out), re.DOTALL)


def has_wildcard(pattern: str) -> bool:
    return any(t in ("*", "?") for t in _TOKEN.findall(pattern))


@dataclass
class Match:
    matched: bool
    pattern: str
    captures: tuple[str, ...] = ()


def match_value(op: str, pattern: str, value: str) -> Match:
    if op in ("StringEquals", "StringNotEquals"):
        return Match(pattern == value, pattern)
    if op == "StringEqualsIgnoreCase":
        return Match(pattern.lower() == value.lower(), pattern)
    if op in ("StringLike", "StringNotLike"):
        m = compile_like(pattern).fullmatch(value)
        return Match(bool(m), pattern, m.groups() if m else ())
    raise ValueError(f"unsupported operator {op!r}")


@dataclass
class ConditionTrace:
    op: str
    key: str
    ok: bool
    hit: Match | None = None
    reason: str = ""


@dataclass
class Verdict:
    allowed: bool
    traces: list[ConditionTrace] = field(default_factory=list)

    def sub_hit(self) -> Match | None:
        for t in self.traces:
            if t.key.endswith(":sub") and t.hit is not None:
                return t.hit
        return None


def _as_list(v):
    return v if isinstance(v, list) else [v]


def eval_condition(condition: dict, context: dict[str, str]) -> Verdict:
    """AND across operators and keys, OR across the values of one key."""
    ctx = {k.lower(): v for k, v in context.items()}
    traces: list[ConditionTrace] = []
    for op, keys in (condition or {}).items():
        if op not in SUPPORTED_OPS:
            raise ValueError(f"operator {op!r} is outside this model")
        for key, wanted in keys.items():
            actual = ctx.get(key.lower())
            patterns = _as_list(wanted)
            if actual is None:
                # absent key: positive operators fail, negated ones pass
                ok = op in NEGATED_OPS
                traces.append(ConditionTrace(op, key, ok, None, "key absent from token"))
                continue
            hits = [match_value(op, p, actual) for p in patterns]
            if op in NEGATED_OPS:
                ok = not any(h.matched for h in hits)
                first = next((h for h in hits if h.matched), None)
            else:
                first = next((h for h in hits if h.matched), None)
                ok = first is not None
            traces.append(ConditionTrace(op, key, ok, first))
    return Verdict(all(t.ok for t in traces), traces)


def evaluate_trust_policy(policy: dict, context: dict[str, str]) -> Verdict:
    """Allow if some Allow statement for AssumeRoleWithWebIdentity matches and
    no Deny statement does. Explicit Deny wins, as in real IAM."""
    allow: Verdict | None = None
    for st in _as_list(policy.get("Statement", [])):
        actions = _as_list(st.get("Action", []))
        if not any(a in ("sts:AssumeRoleWithWebIdentity", "sts:*", "*") for a in actions):
            continue
        v = eval_condition(st.get("Condition", {}), context)
        if st.get("Effect") == "Deny" and v.allowed:
            return Verdict(False, v.traces)
        if st.get("Effect") == "Allow" and v.allowed and allow is None:
            allow = v
    return allow or Verdict(False, [])
