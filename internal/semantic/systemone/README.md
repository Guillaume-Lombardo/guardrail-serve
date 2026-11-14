# systemone

`semantic.PromptInjectionDetector` backed by TypeSafe's System One API
(`POST <base>/v1/systemone`, model Jev), plus a `Cascade` that asks it only when
a primary classifier is unsure. Design: [ADR 0021](../../../docs/adr/0021-systemone-gray-zone-judge.md).
Primary references: [System One API](https://docs.typesafe.ai/api/system-one.md),
[question types](https://docs.typesafe.ai/questions.md),
[models](https://docs.typesafe.ai/models.md),
[errors](https://docs.typesafe.ai/errors.md).

The package reads no environment variable and makes no network call at
construction. Only the Go standard library is used.

## Usage

```go
key, err := systemone.NewAPIKey(secretFromFile)
judge, err := systemone.NewJudge(systemone.Config{
	BaseURL:     "https://api.typesafe.ai",
	Model:       "jev-1.14.0",
	APIKey:      key,
	Question:    systemone.QuestionNoul,
	Threshold:   0.7,
	Timeout:     3 * time.Second,
	FailureMode: httpclassifier.FailClosed,
}, masker, observer)
cascade, err := systemone.NewCascade(primary, judge, systemone.Zone{Lower: 0.3, Upper: 0.9}, observer)
```

`masker` is required: every text goes through `Masker.Mask` before a request is
built, and a masking error sends nothing. The app supplies an internal
`detect_secret` + `detect_pii` masking policy (`internal/app/semantic.go`).
`observer` may be nil. `Judge` and `Cascade` are safe for concurrent use.

## Contract

- One typed question named `prompt_injection` with fixed, compiled-in wording:
  `noul` (probability of yes), `choice` (probability of option `injection`
  among `injection`/`benign`) or `score` (probability of level `2` among
  `0`/`1`/`2`). The masked text is sent only as `state.untrusted_text`, never
  inside the instructions.
- Responses are bounded (64 KiB by default) and decoded strictly: one JSON
  value, model and usage present, exactly one answer of the asked name and type,
  finite probabilities in [0, 1], exact option or level sets, distributions
  summing to 1 within 0.05, and a `choice`/`score` consistent with them.
- Each non-blank text is judged separately with its own `Timeout` (masking
  excluded); the assessment reports the maximum probability and triggers when it
  is `>= Threshold`. Metadata `semantic_rule=systemone_judge`.
- No retry, no redirect, no environment proxy; `https` is required except for a
  loopback host. The key is sent only as `Authorization: Bearer` and renders as
  `[REDACTED]` through `fmt`, `slog` and text marshalling.
- Failures are `*Error` values whose message is the kind (and status code for
  HTTP errors): `unauthorized`, `payment_required`, `rate_limited`, `overloaded`,
  `rejected_input` (400, 413, 422), `status`, `timeout`, `canceled`, `transport`, `masking_failed`,
  `text_too_large`, `response_too_large`, `invalid_response`,
  `invalid_probability`. `FailClosed` returns them; `FailOpen` returns a degraded
  assessment (`classifier_degraded=true`) for provider failures only.
  `canceled`, `masking_failed`, `text_too_large` and `rejected_input` are always
  errors: the last three are provoked by the input, and fail-open must not let
  crafted text disable the judge.

## Cascade

`Cascade` calls the primary first. With primary score `s`: `s < Lower` or
`s > Upper` returns the primary result (no judge call); `Lower <= s <= Upper`
returns the judge result. A primary error, a degraded primary result or a
non-finite score never reaches the judge and is never treated as 0. Routes are
reported to `Observer.ObserveRoute`: `judged`, `below_zone`, `above_zone`,
`primary_failure`, `empty`.
