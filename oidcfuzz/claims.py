"""Build the `sub` claim GitHub puts in an Actions OIDC token.

Formats, per the GitHub OIDC reference (docs.github.com, checked 2026-11-25):

  legacy     repo:OWNER/REPO:<context>
  immutable  repo:OWNER@OWNER_ID/REPO@REPO_ID:<context>

  <context> is one of
    ref:refs/heads/BRANCH | ref:refs/tags/TAG | pull_request | environment:NAME

  * environment wins over everything else when the job declares one
  * pull_request wins over ref when the job has no environment
  * any ':' inside a metadata value is rewritten to '%3A'
  * immutable is the default for repos created after 2026-07-15, for repos
    renamed/transferred after that date, and for repos that opted in
"""
from __future__ import annotations

from dataclasses import dataclass

AUD = "sts.amazonaws.com"  # default audience of aws-actions/configure-aws-credentials
PROVIDER = "token.actions.githubusercontent.com"
SUB_KEY = f"{PROVIDER}:sub"
AUD_KEY = f"{PROVIDER}:aud"


def _enc(value: str) -> str:
    return value.replace(":", "%3A")


@dataclass(frozen=True)
class Identity:
    owner: str
    owner_id: int
    repo: str
    repo_id: int
    fmt: str  # "legacy" | "immutable"
    label: str = ""
    role: str = "other"  # "legit" | "other" | "attacker"

    def prefix(self) -> str:
        if self.fmt == "immutable":
            return f"repo:{self.owner}@{self.owner_id}/{self.repo}@{self.repo_id}"
        return f"repo:{self.owner}/{self.repo}"


@dataclass(frozen=True)
class Context:
    kind: str  # branch | tag | pull_request | environment
    value: str = ""

    def render(self) -> str:
        if self.kind == "branch":
            return f"ref:refs/heads/{_enc(self.value)}"
        if self.kind == "tag":
            return f"ref:refs/tags/{_enc(self.value)}"
        if self.kind == "pull_request":
            return "pull_request"
        if self.kind == "environment":
            return f"environment:{_enc(self.value)}"
        raise ValueError(self.kind)

    @property
    def label(self) -> str:
        return {
            "branch": f"push {self.value}",
            "tag": f"tag {self.value}",
            "pull_request": "pull_request",
            "environment": f"env {self.value}",
        }[self.kind]


def sub_claim(identity: Identity, ctx: Context) -> str:
    return f"{identity.prefix()}:{ctx.render()}"


def token_context(identity: Identity, ctx: Context) -> dict[str, str]:
    """The two condition keys a trust policy can see for AssumeRoleWithWebIdentity."""
    return {SUB_KEY: sub_claim(identity, ctx), AUD_KEY: AUD}
