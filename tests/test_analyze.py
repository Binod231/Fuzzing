import json, pathlib
import pytest
from oidcfuzz.analyze import ALLOW_OK, OUTAGE, OVERREACH, analyze

POL = pathlib.Path(__file__).parent.parent / "policies"

# policy -> (overreach, outage) in the pre-migration phase, then post-migration
GOLDEN = {
    # derived by hand from the scenario table, then compared with the run
    # rows: LL legit-legacy, LI legit-immutable, S sandbox, M marketing, AL acme-labs,
    #       MA mallory, AP stranger-holds-name (legacy sub), AQ post-cutoff re-registration (immutable sub)
    "P1_repo_wildcard":     ((10, 0), (6, 2)),    # pre: LL 4 + AP 6          post: AP 6
    "P2_org_wide":          ((22, 0), (18, 2)),   # pre: LL 4 + S 6 + M 6 + AP 6   post: 18
    "P3_name_prefix":       ((16, 0), (12, 2)),   # pre: LL 4 + S 6 + AP 6    post: 12
    "P4_any_branch":        ((3, 1),  (2, 2)),    # pre: LL feat + AP main,feat; outage LL env
    "P5_exact_legacy":      ((2, 0),  (2, 2)),    # AP main,env accepted in both phases
    "P6_exact_immutable":   ((0, 2),  (0, 0)),
    "P7_exact_dual_format": ((2, 0),  (2, 0)),
    "P8_org_prefix":        ((16, 0), (12, 2)),   # pre: LL 4 + AL 6 + AP 6
    "P9_no_sub_condition":  ((40, 0), (40, 0)),   # everything accepted: 7 rows x 6 contexts = 42 cells, 2 intended
}


def rep(name):
    return analyze(name, json.loads((POL / f"{name}.json").read_text()))


@pytest.mark.parametrize("name", GOLDEN)
def test_golden_counts(name):
    r = rep(name)
    (pre_o, pre_x), (post_o, post_x) = GOLDEN[name]
    assert (r.count(OVERREACH, "pre"), r.count(OUTAGE, "pre")) == (pre_o, pre_x), "pre"
    assert (r.count(OVERREACH, "post"), r.count(OUTAGE, "post")) == (post_o, post_x), "post"


def test_only_immutable_pinned_policy_is_clean_after_migration():
    clean = [n for n in GOLDEN if rep(n).count(OVERREACH, "post") == 0 and rep(n).count(OUTAGE, "post") == 0]
    assert clean == ["P6_exact_immutable"]


def test_dual_format_policy_has_no_outage_in_either_phase():
    r = rep("P7_exact_dual_format")
    assert r.count(OUTAGE, "pre") == 0 and r.count(OUTAGE, "post") == 0


def test_pre_cutoff_reregistered_name_is_accepted_by_every_legacy_exact_policy():
    r = rep("P5_exact_legacy")
    bad = [c.sub for c in r.of(OVERREACH)]
    assert bad == ["repo:acme/payments:ref:refs/heads/main", "repo:acme/payments:environment:prod"]


def test_post_cutoff_reregistered_name_is_rejected_by_legacy_exact_policy():
    r = rep("P5_exact_legacy")
    assert not any("@9001" in c.sub and c.accepted for c in r.cells)
