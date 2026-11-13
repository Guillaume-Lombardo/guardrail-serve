# Evaluation corpora and loaders

Inputs for `cmd/guardrail-eval` (see `cmd/guardrail-eval/README.md` for the
command, the corpus contract and the report format). Everything here is offline:
tests start the real handler with `httptest` and nothing touches the network.

```
tests/eval/
  corpus/guardrail-serve-original-v1.jsonl   original FR/EN corpus (versioned)
  loaders/                                    explicit importers for public datasets
  harness_test.go, imported_test.go           end-to-end tests against the real handler
```

## Original corpus

`corpus/guardrail-serve-original-v1.jsonl` has 83 short texts written for this
repository (license MIT). All secrets, card numbers, emails, IBANs and phone
numbers are fictional or use reserved/documentation values. For each of
`detect_secret`, `detect_pii` and `prompt_injection` it holds French and English
positives and negatives, including negatives that look like positives
(hashes, version numbers, form labels, quoted warnings about injection).

Every case carries explicit labels for the three detectors. The corpus header
defines what a label means:

- `detect_secret`: the text contains a credential (password, API key, token, URL credentials).
- `detect_pii`: email address, French phone number, IBAN, IPv4 address or payment
  card number. Names and postal addresses are out of scope and left unlabelled.
- `prompt_injection`: the text tries to override instructions, reveal hidden
  prompts or disable safeguards.

Cases tagged `hard` stress known heuristic limits. Labels state the **expected**
behaviour, not what the current detectors do: today's false positives (hashes or
IDs flagged as secrets) and false negatives (the injection patterns are
English-only, so French recall is low) appear as metrics and are not hidden by
adjusting labels or detectors. Changing the corpus is a version change: add a new
file (`...-v2.jsonl`) rather than editing a published one.

Run it:

```sh
go run ./cmd/guardrail-eval validate --corpus tests/eval/corpus/guardrail-serve-original-v1.jsonl
go test ./tests/eval/...
```

## Public datasets: BIPIA, AgentDojo, Presidio

`loaders/` converts three public datasets into the corpus format. Data is
**never** downloaded automatically, never committed, and never fetched in tests
or CI. The tests use tiny hand-written fixtures in `loaders/testdata/`.

```sh
go run ./tests/eval/loaders/cmd/eval-import \
  --dataset bipia --output .agent-tmp/imported/bipia.jsonl \
  --url https://raw.githubusercontent.com/microsoft/BIPIA/a004b69ec0dd446e0afd461d98cb5e96e120a5d0/benchmark/text_attack_test.json \
  --revision a004b69ec0dd446e0afd461d98cb5e96e120a5d0 \
  --sha256 75750e7b4e8b34e8f9d88d89b357aeaaf02bd07f9e493ccd37eda74a0cd7c7f8

go run ./tests/eval/loaders/cmd/eval-import \
  --dataset presidio --output .agent-tmp/imported/presidio.jsonl \
  --url https://raw.githubusercontent.com/data-privacy-stack/presidio-research/7f568b6da8a5a403ce199d656f6baefc3e87acbb/tests/data/generated_small.json \
  --revision 7f568b6da8a5a403ce199d656f6baefc3e87acbb \
  --sha256 b40cfe75e5f0799b1c8054d91cbaafd92a7a34b425c1416cdf70ad5ff961fb5d

go run ./tests/eval/loaders/cmd/eval-import \
  --dataset agentdojo --output .agent-tmp/imported/agentdojo.jsonl \
  --url https://raw.githubusercontent.com/ethz-spylab/agentdojo/089ed468cf3ed0322acc66b0211f26d9d90dbf60/runs/Meta-SecAlign-70B-repeat_user_prompt/banking/user_task_0/direct/injection_task_1.json \
  --revision 089ed468cf3ed0322acc66b0211f26d9d90dbf60 \
  --sha256 40d646777f252f0ae0240860192c74a000c4ba82991bbe9e5ec58fa8c5c8f570

go run ./cmd/guardrail-eval run --base-url http://127.0.0.1:8080 \
  --corpus tests/eval/corpus/guardrail-serve-original-v1.jsonl \
  --corpus .agent-tmp/imported/bipia.jsonl \
  --corpus .agent-tmp/imported/presidio.jsonl \
  --corpus .agent-tmp/imported/agentdojo.jsonl
```

- Pass a local file instead with `--input PATH` (repeatable; AgentDojo also takes
  a directory of run traces). `--revision` is then recorded when given.
- With `--url`, the download is HTTPS-only (redirects must stay on HTTPS), bounded
  in size and time (`--timeout`), and rejected unless its SHA-256 equals `--sha256`.
  Pin URLs to a commit, never to a branch, so the digest stays meaningful.
- Output must be under a `.agent-tmp/` directory (ignored by git) unless
  `--allow-any-output` is set. The `tests/eval/.gitignore` also ignores `imported/`.
- `--lang`, `--name`, `--limit` and (Presidio) `--entities` tune the import. The
  corpus header records dataset, URL, revision and digest of the source.
- The importers print what they skipped and why; skipped records are not labelled.

### Mapping and limits

None of these datasets was built to score this service's detectors, so the
imported labels are **not equivalent** to the benchmarks' own metrics and the
numbers must not be compared with published results. Each imported corpus states
its own `label_semantics`; in short:

| Dataset | License (check the source before reuse) | Mapping | Limits |
|---|---|---|---|
| BIPIA (`microsoft/BIPIA`, `benchmark/text_attack_*.json`) | MIT (repository LICENSE; the benchmark's context datasets have their own terms and are not imported) | Each attack instruction becomes a `prompt_injection=true` case. | Positives only, and the instruction is taken out of its email/web/table/code context. BIPIA measures attack success of a model, not detection by a filter. English only. |
| AgentDojo (`ethz-spylab/agentdojo` run traces) | MIT | The text an attack injects into a tool output (the trace's `injections` values) becomes a `prompt_injection=true` case, sent as a `request` input. | Positives only. Many injections ask for an action (send money) instead of overriding instructions, and AgentDojo scores whether an agent obeys, not whether a filter flags it. Everything else in a trace (messages, utility and security results) is ignored. |
| Presidio (`data-privacy-stack/presidio-research`, `tests/data/generated_small.json`) | MIT | A record with a span of a mapped entity (default `EMAIL_ADDRESS`, `CREDIT_CARD`, `IP_ADDRESS`, `IBAN_CODE`) is `detect_pii=true`; a record with no span at all is `false`. | Labels are record-level presence, not span-level. Records whose only spans are other entity types (PERSON, LOCATION, US_SSN…) are skipped, being neither positive nor negative. `PHONE_NUMBER` is unmapped by default because `detect_pii` targets French numbers only; `IP_ADDRESS` may include IPv6, which `detect_pii` does not target. |

Public data may contain content you do not want in a repository (including
offensive or realistic-looking personal data). Keep imports under `.agent-tmp/`,
do not commit them, and do not paste them into issues or PRs.

## Tests

| Test | Covers |
|---|---|
| `harness_test.go` | Shipped corpus is valid and canonical; `annotate` and `enforce` against the real handler; API prefix and API key handling; request errors are not detections. |
| `imported_test.go` | Loader output from the fixtures runs next to the original corpus; corpora stay separate in the report. |
| `loaders/*_test.go` | Mapping, skip rules, pinned download (local `httptest` server), digest mismatch, output-path guard. |
| `cmd/guardrail-eval/eval/*_test.go` | Metrics, zero-denominator rule, client limits, runner, report, CLI. |
