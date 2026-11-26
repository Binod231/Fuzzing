from oidcfuzz import quota


def test_length_grows_linearly_and_crosses_default_before_max():
    rows = quota.sweep(80)
    a, b = quota.first_over(rows, quota.DEFAULT_LIMIT), quota.first_over(rows, quota.MAX_LIMIT)
    assert a is not None and b is not None and a < b
    lens = [l for _, l in rows]
    assert lens == sorted(lens)
