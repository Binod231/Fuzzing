"""Figures: small-multiples verdict grid and the trust-policy-length chart."""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker
from matplotlib.patches import FancyBboxPatch, Patch

from .analyze import ALLOW_OK, DENY_OK, OUTAGE, OVERREACH
from .scenarios import CONTEXTS

# reserved status palette (light surface) + chrome from the reference palette
GOOD, CRIT, SERIOUS = "#0aac23", "#dc3c3d", "#f18a59"
SURFACE, INK, INK2, GRID, NEUTRAL = "#ffffff", "#191919", "#666666", "#e7e7e7", "#efefef"
FILL = {ALLOW_OK: GOOD, OVERREACH: CRIT, OUTAGE: SERIOUS, DENY_OK: NEUTRAL}
GLYPH = {ALLOW_OK: ("✓", "#ffffff"), OVERREACH: ("!", "#ffffff"), OUTAGE: ("×", "#0b0b0b"), DENY_OK: ("", INK)}

SHORT_ROWS = ["acme/payments  legacy sub", "acme/payments  immutable sub", "acme/payments-sandbox",
              "acme/marketing-site", "acme-labs/payments", "mallory/payments",
              "stranger holds old name (legacy)", "re-registered after 2026-07-15"]
SHORT_COLS = ["push main", "push feature/login", "tag v1.2.0", "pull_request", "env prod", "env prod-debug"]

plt.rcParams["font.family"] = ["Inter", "DejaVu Sans"]


def heatmap(reports, path, ncols=3):
    n = len(reports)
    nrows = -(-n // ncols)
    fig, axes = plt.subplots(nrows, ncols, figsize=(17.5, 5.6 * nrows + 1.0), dpi=130)
    fig.patch.set_facecolor(SURFACE)
    for k, ax in enumerate(axes.flat):
        ax.set_facecolor(SURFACE)
        if k >= n:
            ax.axis("off")
            continue
        rep = reports[k]
        grid = rep.grid()
        for r, row in enumerate(grid):
            for c, cell in enumerate(row):
                ax.add_patch(FancyBboxPatch((c + 0.04, r + 0.04), 0.92, 0.92,
                                            boxstyle="round,pad=0,rounding_size=0.12",
                                            fc=FILL[cell.state], ec="none"))
                g, col = GLYPH[cell.state]
                if g:
                    ax.text(c + 0.5, r + 0.52, g, ha="center", va="center", color=col,
                            fontsize=15, fontweight="bold")
        ax.set_xlim(0, len(CONTEXTS))
        ax.set_aspect("equal")
        for s in ax.spines.values():
            s.set_visible(False)
        ax.set_xticks([i + 0.5 for i in range(len(CONTEXTS))])
        ax.set_xticklabels(SHORT_COLS, rotation=40, ha="left", fontsize=8.5, color=INK2)
        ax.xaxis.tick_top()
        ax.set_yticks([i + 0.5 for i in range(len(rep.idents))])
        ax.set_yticklabels(SHORT_ROWS if k % ncols == 0 else [""] * len(rep.idents), fontsize=8.8, color=INK2)
        ax.tick_params(length=0, pad=3)
        name = rep.name.split("_", 1)
        pre_o, pre_x = rep.count(OVERREACH, "pre"), rep.count(OUTAGE, "pre")
        post_o, post_x = rep.count(OVERREACH, "post"), rep.count(OUTAGE, "post")
        base = len(rep.idents)
        ax.text(0, base + 0.55, f"{name[0]}  {name[1].replace('_', ' ')}", fontsize=13,
                fontweight="bold", color=INK, va="top")
        ax.text(0, base + 1.2, f"before migration   {pre_o} over-granted · {pre_x} broken\n"
                               f"after migration     {post_o} over-granted · {post_x} broken",
                fontsize=9.4, color=INK2, va="top", linespacing=1.55)
        ax.set_ylim(base + 2.5, 0)
    handles = [Patch(fc=GOOD, label="✓  accepted, as intended"),
               Patch(fc=CRIT, label="!  accepted, NOT intended (over-granted)"),
               Patch(fc=SERIOUS, label="×  rejected, but intended (pipeline breaks)"),
               Patch(fc=NEUTRAL, label="rejected, correctly")]
    fig.legend(handles=handles, loc="lower center", ncol=4, frameon=False, fontsize=10.5,
               labelcolor=INK, bbox_to_anchor=(0.5, 0.005))
    fig.subplots_adjust(left=0.13, right=0.99, top=0.94, bottom=0.04, wspace=0.08, hspace=0.12)
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)


def quota_chart(rows, path, default_limit=2048, max_limit=8192):
    xs = [n for n, _ in rows]; ys = [l for _, l in rows]
    fig, ax = plt.subplots(figsize=(9.2, 4.6), dpi=140)
    fig.patch.set_facecolor(SURFACE); ax.set_facecolor(SURFACE)
    ax.plot(xs, ys, color="#257de0", lw=2)
    for lim, lab in ((default_limit, "default limit 2,048"), (max_limit, "maximum after increase 8,192")):
        ax.axhline(lim, color=CRIT if lim == max_limit else SERIOUS, lw=1.2, ls=(0, (4, 3)))
        ax.text(xs[-1], lim + 180, lab, ha="right", fontsize=9.5, color=INK2)
    for lim in (default_limit, max_limit):
        n = next(n for n, l in rows if l > lim)
        ax.plot([n], [dict(rows)[n]], "o", ms=8, mfc="#257de0", mec=SURFACE, mew=2)
        ax.annotate(f"{n} repos", (n, dict(rows)[n]), xytext=(8, -16), textcoords="offset points",
                    fontsize=10, color=INK)
    ax.set_xlabel("repositories trusted by one role (each: main push + prod environment, both sub formats)",
                  fontsize=9.5, color=INK2)
    ax.set_ylabel("minified trust policy, characters", fontsize=9.5, color=INK2)
    ax.set_title("Exact-match, dual-format trust policy outgrows the default quota at 10 repos",
                 loc="left", fontsize=12, fontweight="bold", color=INK)
    ax.grid(axis="y", color=GRID, lw=0.8); ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#c2c2c2")
    ax.tick_params(colors=INK2, labelsize=9)
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{int(v):,}"))
    ax.set_xlim(0, xs[-1]); ax.set_ylim(0, max(ys) * 1.04)
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)
