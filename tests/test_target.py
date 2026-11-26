import json
from oidcfuzz.analyze import OVERREACH, OUTAGE, analyze
from oidcfuzz.claims import AUD, AUD_KEY, SUB_KEY
from oidcfuzz.scenarios import Target

T = Target("globex", 77, "billing-api", 88)


def pol(subs):
    return {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                           "Condition": {"StringEquals": {AUD_KEY: AUD, SUB_KEY: subs}}}]}


def test_immutable_pinned_policy_is_clean_for_any_target():
    r = analyze("x", pol(["repo:globex@77/billing-api@88:ref:refs/heads/main",
                          "repo:globex@77/billing-api@88:environment:prod"]), T)
    assert (r.count(OVERREACH, "post"), r.count(OUTAGE, "post")) == (0, 0)


def test_default_target_policy_is_wrong_for_another_target():
    r = analyze("x", pol(["repo:acme@1001/payments@2002:ref:refs/heads/main"]), T)
    assert r.count(OUTAGE, "post") == 2  # the globex pipeline would be locked out
