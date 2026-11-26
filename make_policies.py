"""Write the policy gallery (JSON) used by the post. Each one is a pattern seen in the wild
or in GitHub's own docs, plus two hardened variants."""
import json, pathlib
from oidcfuzz.claims import AUD, AUD_KEY, PROVIDER, SUB_KEY

def pol(op, sub):
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": f"arn:aws:iam::123456789012:oidc-provider/{PROVIDER}"},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {AUD_KEY: AUD}, op: {SUB_KEY: sub}} if op != "StringEquals" else
                     {"StringEquals": {AUD_KEY: AUD, SUB_KEY: sub}}}]}

G = {
 "P1_repo_wildcard":      pol("StringLike",  "repo:acme/payments:*"),
 "P2_org_wide":           pol("StringLike",  "repo:acme/*"),
 "P3_name_prefix":        pol("StringLike",  "repo:acme/payments*"),
 "P4_any_branch":         pol("StringLike",  "repo:acme/payments:ref:refs/heads/*"),
 "P5_exact_legacy":       pol("StringEquals", ["repo:acme/payments:ref:refs/heads/main",
                                              "repo:acme/payments:environment:prod"]),
 "P6_exact_immutable":    pol("StringEquals", ["repo:acme@1001/payments@2002:ref:refs/heads/main",
                                              "repo:acme@1001/payments@2002:environment:prod"]),
 "P7_exact_dual_format":  pol("StringEquals", ["repo:acme/payments:ref:refs/heads/main",
                                              "repo:acme/payments:environment:prod",
                                              "repo:acme@1001/payments@2002:ref:refs/heads/main",
                                              "repo:acme@1001/payments@2002:environment:prod"]),
 "P8_org_prefix":         pol("StringLike",  "repo:acme*/payments:*"),
 "P9_no_sub_condition":   {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow",
        "Principal": {"Federated": f"arn:aws:iam::123456789012:oidc-provider/{PROVIDER}"},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {AUD_KEY: AUD}}}]},
}
out = pathlib.Path("policies"); out.mkdir(exist_ok=True)
for k, v in G.items():
    (out / f"{k}.json").write_text(json.dumps(v, indent=2) + "\n")
print("wrote", len(G), "policies")
