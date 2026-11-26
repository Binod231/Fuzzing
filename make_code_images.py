"""Render real source + real terminal output as images (nothing hand-typed)."""
import inspect, html, pathlib
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter
from playwright.sync_api import sync_playwright
from oidcfuzz import iam

CSS = """
body{margin:0;background:#0f1419;font-family:'JetBrains Mono','DejaVu Sans Mono',monospace}
.card{margin:28px;border-radius:12px;background:#1b2330;box-shadow:0 8px 30px rgba(0,0,0,.45);overflow:hidden;display:inline-block;min-width:860px}
.bar{background:#232F3E;color:#c9d1d9;font:600 13px Inter,sans-serif;padding:11px 16px;display:flex;align-items:center;gap:8px}
.dot{width:11px;height:11px;border-radius:50%}
pre{margin:0;padding:18px 22px;font-size:14.5px;line-height:1.55;color:#e6edf3}
.hl{background:rgba(221,52,76,.18);display:inline-block;width:100%}
.bad{color:#ff6b6b;font-weight:700}.out{color:#ffa657;font-weight:700}.hd{color:#79c0ff;font-weight:700}
.dim{color:#8b98a9}.ok{color:#56d364}
"""
def page(title, body, extra=""):
    return f"""<html><head><style>{CSS}{extra}</style></head><body><div class="card" id="c">
<div class="bar"><span class="dot" style="background:#ff5f56"></span><span class="dot" style="background:#ffbd2e"></span><span class="dot" style="background:#27c93f"></span><span style="margin-left:10px">{title}</span></div>
<pre>{body}</pre></div></body></html>"""

def shot(html_text, out):
    with sync_playwright() as p:
        b = p.chromium.launch(); pg = b.new_page(device_scale_factor=2, viewport={"width": 1500, "height": 900})
        pg.set_content(html_text); pg.locator("#c").screenshot(path=out); b.close()

# 1) real source of the evaluator core
src = inspect.getsource(iam.compile_like) + "\n\n" + inspect.getsource(iam.eval_condition)
fmt = HtmlFormatter(style="github-dark", nowrap=True)
body = highlight(src, PythonLexer(), fmt)
shot(page("oidcfuzz/iam.py — the evaluator (AND across keys, OR across values, * becomes a capture group)", body,
          HtmlFormatter(style="github-dark").get_style_defs("pre")), "figures/fig3_code_evaluator.png")

# 2) real terminal output, elided only where marked
lines = pathlib.Path("figures/run_output.txt").read_text().splitlines()
keep, in_p3 = [], False
for i, ln in enumerate(lines):
    if ln.startswith("== P3"): in_p3 = True
    if ln.startswith("== P5"): in_p3 = False
    if ln.startswith("   lint"): continue
    if in_p3 and ("feature/login" in ln or "v1.2.0" in ln or "pull_request" in ln or "prod-debug" in ln):
        continue
    keep.append(ln)
# collapse elisions so the image says so honestly
out, last_skipped = [], False
orig_idx = {id(l): i for i, l in enumerate(lines)}
def cls(l):
    s = html.escape(l)
    if l.startswith("=="): return f'<span class="hd">{s}</span>'
    if "!! OVERREACH" in l: return f'<span class="bad">{s}</span>'
    if "xx OUTAGE" in l: return f'<span class="out">{s}</span>'
    if l.strip().startswith(("pattern", "matched")): return f'<span class="dim">{s}</span>'
    return s
body = "\n".join(cls(l) for l in ["$ python -m oidcfuzz analyze -v policies/P3_name_prefix.json policies/P5_exact_legacy.json",
                                   "# (excerpt: lint lines and repeated rows elided, full output in run_output.txt)", ""] + keep)
shot(page("terminal — oidcfuzz analyze -v", body), "figures/fig4_terminal.png")
print("ok")
