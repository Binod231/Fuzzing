import json, pathlib
from oidcfuzz.analyze import analyze
from oidcfuzz import quota, render
reports = [analyze(p.stem, json.loads(p.read_text())) for p in sorted(pathlib.Path("policies").glob("*.json"))]
render.heatmap(reports, "figures/fig2_verdict_grid.png")
render.quota_chart(quota.sweep(80), "figures/fig5_quota.png")
print("ok", len(reports))
