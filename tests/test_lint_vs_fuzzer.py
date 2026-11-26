import json, pathlib
from oidcfuzz.analyze import OVERREACH, analyze
from oidcfuzz.lint import CRITICAL, WARN, lint

POL = pathlib.Path(__file__).parent.parent / "policies"
SECURITY = {"NO_SUB", "WILDCARD_IN_IDENTITY", "ORG_WIDE", "WILDCARD_CONTEXT", "WILDCARD_REF"}


def both(name):
    pol = json.loads((POL / f"{name}.json").read_text())
    flagged = any(f.code in SECURITY for f in lint(pol))
    return flagged, analyze(name, pol).count(OVERREACH, "post") > 0


def test_linter_never_misses_a_wildcard_overreach():
    # every policy that overreaches after migration through a wildcard must be flagged
    for n in ["P1_repo_wildcard", "P2_org_wide", "P3_name_prefix", "P8_org_prefix", "P9_no_sub_condition"]:
        flagged, over = both(n)
        assert over and flagged, n


def test_only_the_immutable_pinned_policy_is_clean_in_both_tools():
    flagged, over = both("P6_exact_immutable")
    assert not flagged and not over


def test_the_blind_spot_namespace_recycling_is_only_visible_dynamically():
    for n in ("P5_exact_legacy", "P7_exact_dual_format"):
        pol = json.loads((POL / f"{n}.json").read_text())
        assert not any(f.code in SECURITY for f in lint(pol)), n   # linter is blind...
        assert analyze(n, pol).count(OVERREACH, "pre") == 2, n     # ...the fuzzer is not


def test_p4_is_not_misreported_as_org_wide():  # regression: found by the fuzzer on first run
    pol = json.loads((POL / "P4_any_branch.json").read_text())
    assert "ORG_WIDE" not in {f.code for f in lint(pol)}
