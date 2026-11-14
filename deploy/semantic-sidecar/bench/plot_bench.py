"""Comparative chart of the semantic model bench (bench-test split only).

Reads the results JSON written by `guardrail-bench report` and draws recall and
false-positive rate per configuration with 95% Wilson intervals. No model, key
or network. Usage: plot_bench.py <results.json> <out.png>
"""

import json
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e4e3df"
SERIES = "#2a78d6"


def rows_for(results):
    """One row per configuration on bench-test (first run of each config)."""
    seen, rows = set(), []
    for row in results["rows"]:
        if row["corpus"] != "bench-test" or row["slice"] != "all" or row["config"] in seen:
            continue
        seen.add(row["config"])
        rows.append(row)
    rows.sort(key=lambda r: (-r["recall"]["value"], r["fpr"]["value"], r["config"]))
    return rows


def main(argv):
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as handle:
        results = json.load(handle)
    rows = rows_for(results)
    reference = results["decision"]["reference"]
    max_fp = results["decision"]["max_fp"]
    labels = [r["config"] + ("  (reference)" if r["config"] == reference else "") for r in rows]

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "text.color": INK,
                         "axes.labelcolor": INK_2, "xtick.color": INK_2, "ytick.color": INK})
    height = 1.2 + 0.32 * len(rows)
    figure, axes = plt.subplots(1, 2, figsize=(11, height), sharey=True, facecolor=SURFACE)
    for axis, key, title in ((axes[0], "recall", "Recall (attacks detected)"),
                             (axes[1], "fpr", "False-positive rate (benign texts flagged)")):
        axis.set_facecolor(SURFACE)
        for index, row in enumerate(rows):
            rate = row[key]
            if not rate["defined"]:
                continue
            axis.plot([100 * rate["low"], 100 * rate["high"]], [index, index], color=SERIES, linewidth=2,
                      alpha=0.45, solid_capstyle="round")
            axis.plot(100 * rate["value"], index, "o", color=SERIES, markersize=7,
                      markeredgecolor=SURFACE, markeredgewidth=1.5)
            axis.annotate(f'{rate["num"]}/{rate["den"]}', (100 * rate["high"], index), xytext=(5, 0),
                          textcoords="offset points", va="center", fontsize=8, color=INK_2)
        axis.set_title(title, loc="left", fontsize=10, color=INK)
        axis.set_xlim(0, 112)
        axis.set_xticks(range(0, 101, 20))
        axis.set_xticklabels([f"{v}%" for v in range(0, 101, 20)])
        axis.grid(axis="x", color=GRID, linewidth=0.8)
        axis.set_axisbelow(True)
        for side in ("top", "right", "left"):
            axis.spines[side].set_visible(False)
        axis.spines["bottom"].set_color(GRID)
        axis.tick_params(axis="y", length=0)
    negatives = rows[0]["counts"]["fp"] + rows[0]["counts"]["tn"] + rows[0].get("errors_on_negatives", 0)
    axes[1].axvline(100 * 0.05, color=INK_2, linestyle=(0, (3, 3)), linewidth=1)
    axes[1].annotate(f"D1 bar: FPR <= 5% ({max_fp}/{negatives})", (5, len(rows) - 0.4), xytext=(4, 0),
                     textcoords="offset points", fontsize=8, color=INK_2)
    axes[0].set_yticks(range(len(rows)))
    axes[0].set_yticklabels(labels)
    axes[0].invert_yaxis()
    figure.suptitle("guardrail-serve semantic bench, French held-out test split (160 synthetic texts, 80/80); "
                    "dots = point estimate, bars = 95% Wilson interval", x=0.01, ha="left", fontsize=9, color=INK_2)
    figure.tight_layout(rect=(0, 0, 1, 0.97))
    figure.savefig(argv[2], dpi=150, facecolor=SURFACE)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
