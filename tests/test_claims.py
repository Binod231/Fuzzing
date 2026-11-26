from oidcfuzz.claims import Context, Identity, sub_claim

L = Identity("octo-org", 123456, "octo-repo", 456789, "legacy")
I = Identity("octo-org", 123456, "octo-repo", 456789, "immutable")


def test_formats_match_github_docs_examples():
    assert sub_claim(L, Context("branch", "main")) == "repo:octo-org/octo-repo:ref:refs/heads/main"
    assert sub_claim(I, Context("branch", "main")) == "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main"
    assert sub_claim(L, Context("environment", "prod")) == "repo:octo-org/octo-repo:environment:prod"
    assert sub_claim(L, Context("pull_request")) == "repo:octo-org/octo-repo:pull_request"
    assert sub_claim(L, Context("tag", "demo-tag")) == "repo:octo-org/octo-repo:ref:refs/tags/demo-tag"


def test_colon_in_value_is_percent_encoded():
    # docs example: environment `Production:V1` -> `Production%3AV1`
    assert sub_claim(L, Context("environment", "Production:V1")).endswith("environment:Production%3AV1")


def test_environment_name_cannot_inject_a_fake_ref():
    s = sub_claim(L, Context("environment", "prod:ref:refs/heads/main"))
    assert s == "repo:octo-org/octo-repo:environment:prod%3Aref%3Arefs/heads/main"
    assert ":ref:refs/heads/main" not in s
