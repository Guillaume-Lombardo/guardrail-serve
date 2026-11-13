# guardrail-eval

`guardrail-eval` measures a running guardrail-serve from the outside. It sends
labelled texts through the documented HTTP API and reports, per detector, the
confusion matrix (TP/FP/TN/FN) with precision, recall and false positive rate.

It imports nothing from `internal/`: the only coupling to the service is the
public HTTP contract (ADR 0007) and the local JSON contracts below. The design
rationale is in `docs/adr/0011-http-evaluation-harness.md`; the shipped corpus
and the public-dataset loaders are documented in `tests/eval/README.md`.

## Usage

```sh
go run ./cmd/guardrail-eval validate --corpus tests/eval/corpus/guardrail-serve-original-v1.jsonl

go run ./cmd/guardrail-eval run \
  --corpus tests/eval/corpus/guardrail-serve-original-v1.jsonl \
  --base-url http://127.0.0.1:8080 \
  --format json --output .agent-tmp/report.json
```

`validate` checks corpus files offline and sends nothing. `run` accepts
`--corpus` several times; each corpus is evaluated and reported on its own.

| Flag | Default | Meaning |
|---|---|---|
| `--corpus FILE` | required, repeatable | Corpus file (format v1). |
| `--base-url URL` | `$GUARDRAIL_EVAL_BASE_URL` | Service root, including `API_PREFIX` if the service sets one (for example `http://host:8080/v1`). |
| `--mode` | `annotate` | `annotate` or `enforce` (see below). |
| `--policy NAME` | `audit` | Policy used in `annotate` mode. Rejected with `enforce`. |
| `--format` | `text` | `text` (readable) or `json` (machine report). |
| `--output FILE` | stdout | Write the report to a file instead of stdout. |
| `--timeout` | `10s` | Per-request timeout. |
| `--run-timeout` | `0` (off) | Overall run timeout. |
| `--max-response-bytes` | `4194304` | Largest accepted response body. |
| `--max-consecutive-errors` | `5` | Abort after this many consecutive request errors (`0` disables). |
| `--api-key-file FILE` | | File holding the API key (see Authentication). |
| `--auth-scheme` | `bearer` | `bearer` (`Authorization: Bearer`) or `x-api-key`. |
| `--allow-insecure-auth` | off | Allow sending the key over plain `http` to a non-loopback host. |

Requests are sequential. The service allows two concurrent requests by default
(`HTTP_MAX_CONCURRENT_REQUESTS`), so a sequential client never trips that limit.
`SIGINT`/`SIGTERM` cancel the run through its context; a partial report is
still written with status `aborted`.

## Modes

| Mode | Routes | What is compared |
|---|---|---|
| `annotate` | `POST {base}/v1/guardrails/{policy}`, one request per case | A detector is *detected* when the response has at least one finding whose `detector` is that detector. Findings do not depend on the policy action, so any policy that runs the detector on the case's stage works; the default `audit` policy annotates all three. |
| `enforce` | `POST {base}/scan/secrets`, `/scan/pii`, `/scan/prompt-injection`, one request per case and labelled detector | A detector is *detected* when the decision is not `NONE` (`BLOCKED`, `GUARDRAIL_INTERVENED`). |

A case's `input_type` (`request` or `response`) is sent as the stage, so
response-only behaviour (for example injection in a tool result) can be labelled.

Responses that are not detection outcomes never enter the counts: transport
errors, non-2xx statuses, bodies above `--max-response-bytes`, invalid JSON, and
payload-limit blocks (`max_length`, `limit_exceeded`). They are reported under
`errors` and in the per-detector `errored` counter.

## Authentication

There is deliberately no `--api-key` flag: command lines end up in process lists
and shell history. Provide the key with either

- `GUARDRAIL_EVAL_API_KEY` in the environment, or
- `--api-key-file FILE` (at most 4096 bytes, surrounding whitespace trimmed; use a file readable only by you).

Setting both is a usage error.

The key is never written to reports, errors or logs. Redirects are disabled so
the key cannot be forwarded to another host. Sending a key over plain `http` to
a host other than loopback is refused unless `--allow-insecure-auth` is set.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Run complete, every request succeeded (or `validate` passed). |
| 1 | Unexpected local failure, such as an unwritable `--output`. |
| 2 | Usage, configuration or corpus error. No request was sent. |
| 3 | Every case was attempted but some requests failed. The report is written. |
| 4 | Run aborted (consecutive errors, timeout or signal). The report is partial. |

Errors go to stderr as `guardrail-eval: error: ...`; the report goes to stdout
or `--output`. A detection result (even a bad one) never changes the exit code:
thresholds belong to the caller (L7b).

## Metrics

For each detector and each corpus: `TP` (labelled and detected), `FP` (not
labelled, detected), `TN`, `FN`.

- `precision = TP / (TP + FP)`
- `recall = TP / (TP + FN)`
- `fpr = FP / (FP + TN)`

**Zero-denominator rule.** A metric whose denominator is zero is *undefined*.
JSON reports it as `{"value": 0, "defined": false}` (never `NaN`, never `null`)
and text as `n/a`. Consumers must read `defined` before comparing `value`.

**Aggregation.** `aggregate.micro` sums the confusion matrices of all detectors
in the corpus and derives the metrics from the sums. `aggregate.macro` averages
each metric over the detectors where it is defined (and is undefined when none
is). Corpora are never pooled: labels from different sources are not
equivalent, so each corpus has its own `detectors` and `aggregate`.

## Report format (version 1)

`--format json` output is deterministic: no timestamps or durations, sorted keys,
so equal inputs on a deterministic service give byte-identical reports. Breaking
changes bump `report_version`.

```json
{
  "report_version": 1,
  "status": "complete",
  "target": {"base_url": "http://127.0.0.1:8080", "mode": "annotate", "policy": "audit"},
  "corpora": [
    {
      "name": "guardrail-serve-original-v1",
      "cases": 83,
      "sha256": "…",
      "detectors": {
        "detect_pii": {
          "counts": {"tp": 13, "fp": 7, "tn": 63, "fn": 0},
          "metrics": {
            "precision": {"value": 0.65, "defined": true},
            "recall": {"value": 1, "defined": true},
            "fpr": {"value": 0.1, "defined": true}
          },
          "errored": 0,
          "by_language": {"en": {"counts": {}, "metrics": {}}},
          "by_tag": {"hard": {"counts": {}, "metrics": {}}}
        }
      },
      "aggregate": {"micro": {"counts": {}, "metrics": {}}, "macro": {}}
    }
  ],
  "run": {"cases": 83, "cases_errored": 0, "requests": 83},
  "errors": {"total": 0, "by_kind": {}, "samples": [], "truncated": false},
  "warnings": []
}
```

(`{}` above abbreviates the same shape; `jq` paths are stable across runs.)

- `status`: `complete`, `complete_with_errors` (some requests failed) or `aborted`.
- `errors.by_kind` keys: `transport`, `http_status`, `invalid_response`,
  `response_too_large`, `limit_exceeded`. `errors.samples` lists at most 20 failures.
- `warnings`: for example an `annotate` run where a labelled detector never
  reported a finding in a corpus, which usually means the policy does not run it.

Example for a regression check (L7b adds the real gates):

```sh
jq '.corpora[0].detectors.detect_secret.metrics.recall' .agent-tmp/report.json
```

## Corpus format (version 1)

JSON Lines. The first line is a header, every other non-empty line is a case.
Unknown fields are rejected and errors name the offending line.

```jsonl
{"format":"guardrail-eval-corpus","version":1,"name":"demo","description":"…","license":"MIT","label_semantics":"what a true label means","source":{"dataset":"…","url":"…","revision":"…","sha256":"…"}}
{"id":"secret-en-001","lang":"en","input_type":"request","text":"password=hunter2-demo","labels":{"detect_secret":true,"detect_pii":false},"tags":["password"]}
```

- Header: `format` (`guardrail-eval-corpus`), `version` (`1`), `name`
  (`^[a-z0-9][a-z0-9._-]{0,63}$`); optional `description`, `license`,
  `label_semantics`, `source`.
- Case: `id` (unique, `^[a-z0-9][a-z0-9._-]{0,95}$`), `lang` (2-3 lowercase letters, such as `fr`),
  `text` (non-blank, at most 20000 runes, the service limit), `labels`
  (detector name → bool, at least one), optional `input_type`
  (`request` default, or `response`), optional `tags`.
- Detectors are free-form names (`^[a-z][a-z0-9_]{0,63}$`). `enforce` mode needs
  a `/scan` route, so it supports `detect_secret`, `detect_pii` and
  `prompt_injection`; `annotate` accepts any detector name the policy reports.
  A detector that a case does not label is not evaluated on that case.
