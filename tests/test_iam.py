import random
from oidcfuzz.iam import compile_like, eval_condition, match_value, evaluate_trust_policy


def ref_like(p: str, s: str) -> bool:
    """Independent recursive reference for * and ? (no escapes)."""
    if not p:
        return not s
    if p[0] == "*":
        return any(ref_like(p[1:], s[i:]) for i in range(len(s) + 1))
    if not s:
        return False
    return (p[0] == "?" or p[0] == s[0]) and ref_like(p[1:], s[1:])


def test_differential_against_reference():
    rnd = random.Random(1337)
    alphabet = "ab:/@-"
    for _ in range(4000):
        pat = "".join(rnd.choice(alphabet + "**??") for _ in range(rnd.randint(0, 7)))
        val = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 9)))
        assert bool(compile_like(pat).fullmatch(val)) == ref_like(pat, val), (pat, val)


def test_star_crosses_colon_and_slash():
    assert match_value("StringLike", "repo:acme/*", "repo:acme/x:ref:refs/heads/a/b").matched


def test_case_sensitive():
    assert not match_value("StringEquals", "repo:Acme/x", "repo:acme/x").matched
    assert not match_value("StringLike", "repo:Acme/*", "repo:acme/x").matched


def test_escapes_are_literal():
    assert match_value("StringLike", "a${*}b", "a*b").matched
    assert not match_value("StringLike", "a${*}b", "axb").matched


def test_list_is_or_keys_are_and():
    cond = {"StringEquals": {"k1": ["a", "b"], "k2": "z"}}
    assert eval_condition(cond, {"k1": "b", "k2": "z"}).allowed
    assert not eval_condition(cond, {"k1": "c", "k2": "z"}).allowed
    assert not eval_condition(cond, {"k1": "a", "k2": "q"}).allowed


def test_missing_key():
    assert not eval_condition({"StringEquals": {"k": "a"}}, {}).allowed
    assert eval_condition({"StringNotEquals": {"k": "a"}}, {}).allowed


def test_explicit_deny_wins():
    pol = {"Statement": [
        {"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringLike": {"k": "*"}}},
        {"Effect": "Deny", "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {"k": "bad"}}},
    ]}
    assert evaluate_trust_policy(pol, {"k": "ok"}).allowed
    assert not evaluate_trust_policy(pol, {"k": "bad"}).allowed


def test_captures_show_what_star_swallowed():
    m = match_value("StringLike", "repo:acme/payments*", "repo:acme/payments-sandbox:pull_request")
    assert m.matched and m.captures == ("-sandbox:pull_request",)
