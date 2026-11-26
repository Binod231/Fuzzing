"""How big does a dual-format, least-privilege trust policy get?

AWS limit (docs.aws.amazon.com IAM quotas, checked 2026-11-25): role trust policy
length defaults to 2,048 characters and can be raised to 8,192. We measure the
minified JSON length, which is a conservative proxy: whitespace handling by
the service is not something this repo claims to know.
"""
from __future__ import annotations

import json

from .claims import AUD, AUD_KEY, PROVIDER, SUB_KEY

DEFAULT_LIMIT, MAX_LIMIT = 2048, 8192


def exact_subs(repos: list[tuple[str, int, str, int]], contexts: list[str]) -> list[str]:
    subs: list[str] = []
    for owner, oid, repo, rid in repos:
        for ctx in contexts:
            subs.append(f"repo:{owner}/{repo}:{ctx}")
            subs.append(f"repo:{owner}@{oid}/{repo}@{rid}:{ctx}")
    return subs


def build_policy(repos, contexts, account="123456789012") -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": f"arn:aws:iam::{account}:oidc-provider/{PROVIDER}"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {AUD_KEY: AUD, SUB_KEY: exact_subs(repos, contexts)}},
        }],
    }


def minified_len(policy: dict) -> int:
    return len(json.dumps(policy, separators=(",", ":")))


def sweep(max_repos: int = 80, contexts=("ref:refs/heads/main", "environment:prod")):
    """Length of the exact-match dual-format policy for 1..max_repos repositories."""
    rows = []
    for n in range(1, max_repos + 1):
        repos = [("acme", 1001, f"service-{i:02d}", 2000 + i) for i in range(n)]
        rows.append((n, minified_len(build_policy(repos, list(contexts)))))
    return rows


def first_over(rows, limit: int):
    for n, length in rows:
        if length > limit:
            return n
    return None
