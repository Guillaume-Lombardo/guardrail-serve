"""Measure recall, false-positive rate and latency of a running sidecar on a labeled JSONL file.

Corpus-independent reproducer: it reads any JSON-lines file and prints a report.
It calls the sidecar's `/classify` directly (model-only latency, no Go service,
no chunking), one text per request unless --batch is given.

    python3 tools/measure.py --url http://127.0.0.1:8080/classify --input cases.jsonl \
        --text-field text --label-field label --positive-values injection,attack,1 \
        --thresholds 0.5,0.8,0.9,0.95 --warmup 3

Standard library only. The report contains aggregate numbers, never the texts.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
import time
import urllib.error
import urllib.request


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return math.nan
    rank = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return ordered[rank]


def classify(url: str, texts: list[str], timeout: float) -> list[float]:
    request = urllib.request.Request(
        url, data=json.dumps({"texts": texts}).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-chosen URL
        scores = json.load(response)["scores"]
    if len(scores) != len(texts):
        raise ValueError("wrong number of scores")
    return scores


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--label-field", default="label")
    parser.add_argument("--positive-values", required=True, help="comma-separated label values counted as attacks")
    parser.add_argument("--thresholds", default="0.5,0.8,0.9,0.95")
    parser.add_argument("--batch", type=int, default=1)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    positives = {value.strip().lower() for value in args.positive_values.split(",")}
    thresholds = [float(value) for value in args.thresholds.split(",")]
    cases: list[tuple[str, bool]] = []
    with open(args.input, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            try:
                cases.append((row[args.text_field], str(row[args.label_field]).lower() in positives))
            except KeyError:
                print(f"line {number}: missing field", file=sys.stderr)
                return 2
    if not cases:
        print("no cases", file=sys.stderr)
        return 2

    try:
        for text, _ in cases[: args.warmup]:
            classify(args.url, [text], args.timeout)
        scores: list[float] = []
        latencies: list[float] = []
        for start in range(0, len(cases), args.batch):
            batch = [text for text, _ in cases[start : start + args.batch]]
            began = time.perf_counter()
            scores.extend(classify(args.url, batch, args.timeout))
            latencies.append((time.perf_counter() - began) * 1000)
    except (urllib.error.URLError, ValueError, KeyError, TimeoutError, OSError) as exc:
        print(f"measurement failed: {type(exc).__name__}", file=sys.stderr)
        return 1

    labels = [positive for _, positive in cases]
    attacks = sum(labels)
    benign = len(labels) - attacks
    print(f"cases={len(cases)} attacks={attacks} benign={benign} batch={args.batch}")
    print(f"latency_ms per request: p50={percentile(latencies, 0.5):.1f} p95={percentile(latencies, 0.95):.1f} "
          f"mean={statistics.fmean(latencies):.1f} max={max(latencies):.1f}")
    print("threshold  recall  fpr   (recall = TP/attacks, fpr = FP/benign)")
    for threshold in thresholds:
        tp = sum(1 for score, positive in zip(scores, labels) if positive and score >= threshold)
        fp = sum(1 for score, positive in zip(scores, labels) if not positive and score >= threshold)
        recall = tp / attacks if attacks else math.nan
        fpr = fp / benign if benign else math.nan
        print(f"{threshold:<9.3f}  {recall:6.3f}  {fpr:6.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
