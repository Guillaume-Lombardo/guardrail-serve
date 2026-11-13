# plan.md

## Purpose

This file is intentionally collaborative.
Before major implementation, the agent and the user align on scope, priorities, and constraints.
The plan is then updated here and used as the execution reference.

## Planning Protocol (Agent)

For any non-trivial feature or migration:

1. Confirm the current problem and target outcome.
2. Confirm:
   - business goal
   - in-scope and out-of-scope
   - constraints (performance, compatibility, infra, dependencies, deployment)
   - acceptance criteria
3. Propose a short, testable implementation plan.
4. Keep this file synchronized with decisions and status.
5. For any architecture or structure decision, create or update an ADR in `docs/adr/` and reference it here.

## Initiative: Go Guardrail Service Bootstrap

- Status: `completed`
- Owner: `agent`
- Objective:
  Build a native Go implementation of the archived Python guardrail API, starting with deterministic request/response guardrails on `/scan/*` and `/beta/litellm_basic_guardrail_api`.
- In scope:
  - update repo governance/tooling artifacts from Python-package assumptions to Go-service assumptions
  - define a first Go architecture with explicit domain, config, registry, transport, and resource boundaries
  - implement deterministic guardrails for secrets, PII, prompt injection, and payload size
  - preserve the decision contract `NONE | BLOCKED | GUARDRAIL_INTERVENED`
  - serve `/scan/secrets`, `/scan/pii`, `/scan/prompt-injection`, and `/beta/litellm_basic_guardrail_api`
  - support configurable pattern YAML overrides and embedded defaults
  - add unit, integration, and end-to-end coverage for the main flows
  - initialize local git history and prepare the GitHub bootstrap workflow
- Out of scope:
  - mandatory embedding or LLM providers in the first cut
  - full feature parity with every Python-only implementation detail
  - production Kubernetes manifests or full release automation
  - committing any file from `archive/`
- Constraints:
  - `archive/` is a read-only functional reference and must never be committed
  - prefer deterministic and fast guardrails first
  - leave explicit extension points for embedding- and LLM-backed guardrails
  - keep Docker/runtime footprint small
- Risks:
  - overfitting to the archived Python internals instead of preserving only the useful external contract
  - introducing unnecessary dependencies too early
  - under-specifying the GitHub bootstrap step before remote ownership/auth is known
- Acceptance criteria:
  - governance and local skills reflect a Go-first project
  - an ADR documents the chosen service architecture
  - the Go service exposes the target routes and decision schema
  - deterministic redaction/blocking behavior is covered by tests
  - repository bootstrap is ready for initial GitHub publication once remote details are available
- ADR impact: `required`
- ADR reference(s): `docs/adr/0001-go-guardrail-service-foundation.md`

#### Steps

- [x] Audit governance artifacts and archived Python behavior.
- [x] Update governance/tooling artifacts for the Go migration.
- [x] Record the first architectural decision in an ADR.
- [x] Implement the Go service and deterministic guardrails.
- [x] Add unit, integration, and end-to-end tests.
- [x] Initialize git locally and prepare GitHub bootstrap details.

#### Validation

- [x] `gofmt -w .`
- [x] `go test ./...`
- [x] `go test ./tests/integration/...`
- [x] `go test ./tests/end2end/...`
- [x] `pre-commit run --all-files`

#### Notes / Decisions

- Decision: Start with deterministic regex-based and size-based guardrails in-process, and keep embeddings/LLM as optional future adapters.
- Rationale: This matches the user goal of speed, determinism, and small deployment images while preserving a path for richer guardrails later.
- Follow-up: Extend the service with optional embedding-backed and LLM-backed guardrails on a future dedicated branch.
- GitHub bootstrap: repository created and `main` pushed to `https://github.com/Guillaume-Lombardo/guardrail-serve`.
- ADR record: `docs/adr/0001-go-guardrail-service-foundation.md`
- Closure note: validation now passes from the dedicated branch `codex/phase2-contract-hardening`, restoring compliance with the repository delivery workflow.

## Initiative: Phase 2 Contract Hardening

- Status: `in_progress`
- Owner: `agent`
- Objective:
  Harden the first Go API contract before adding semantic guardrails by tightening request validation, clarifying HTTP error behavior, and covering config/resource override behavior with targeted tests.
- In scope:
  - review and tighten JSON request validation for supported fields and edge cases
  - make HTTP error responses explicit and consistent across route families
  - validate config parsing and boundary defaults for environment-driven settings
  - validate YAML resource override loading behavior with focused integration coverage
  - propagate a request-scoped context through the HTTP handling and guardrail execution path
  - add configurable structured logging with JSON and human-readable output modes
  - log request outcomes with enough context to analyze successes and failures in production
  - update README and related docs if public behavior or config expectations change
- Out of scope:
  - embedding-backed guardrails
  - LLM-provider integrations
  - large transport refactors or framework changes
  - release automation expansion beyond the current workflows
- Constraints:
  - preserve the current decision contract `NONE | BLOCKED | GUARDRAIL_INTERVENED`
  - keep the implementation stdlib-first and dependency-light
  - do not broaden the public API surface without documenting it
  - keep tests deterministic with fixed fixtures and no hidden network access
- Risks:
  - over-correcting validation in a way that breaks intended compatibility with the archived external contract
  - mixing behavioral hardening with larger feature work and losing review clarity
- Acceptance criteria:
  - malformed or unsupported requests produce explicit and consistent HTTP responses
  - config defaults and invalid env values are covered by tests
  - override resource loading behavior is covered by tests
  - README/config docs match the enforced runtime contract
- ADR impact: `yes`
- ADR reference(s): `docs/adr/0001-go-guardrail-service-foundation.md`, `docs/adr/0002-request-context-and-structured-logging.md`

#### Steps

- [x] Audit the current HTTP/request/config contract and identify the missing edge cases.
- [x] Add failing tests for the selected contract-hardening cases.
- [x] Implement the validation and error-handling adjustments.
- [x] Add config/resource override coverage.
- [x] Update documentation if the contract becomes stricter or clearer.
- [x] Run formatting, unit, integration, end-to-end, and pre-commit validation.

#### Validation

- [x] `gofmt -w .`
- [x] `go test ./...`
- [x] `go test ./tests/integration/...`
- [x] `go test ./tests/end2end/...`
- [x] `pre-commit run --all-files`

#### Notes / Decisions

- Decision: Prioritize contract hardening before optional semantic guardrails.
- Rationale: The current base is functional; the highest-value next step is to stabilize inputs, errors, and config behavior so future adapters do not accumulate ambiguity on top of an underspecified API.
- Implemented in this first Phase 2 slice:
  - method-not-allowed responses now use the JSON error contract
  - request bodies with trailing JSON content are rejected as invalid
  - non-positive `MAX_TEXT_ITEMS` and `MAX_TEXT_CHARS` values now fall back to defaults
  - resource override precedence and default fallback are covered by tests
- Planned in the next Phase 2 slice:
  - introduce request-scoped context propagation from HTTP entrypoints into guardrail execution
  - emit structured request logs with configurable `human` or `json` formatting
  - include contextual fields such as request id, route, guardrail, scope, decision, status, and duration in request logs
- Implemented in the second Phase 2 slice:
  - request-scoped context is now propagated through the HTTP handling and guardrail execution path
  - request completion logs now support `human` and `json` formats
  - `X-Request-ID` is echoed back to clients and included in structured request logs
  - a dedicated ADR records the observability decision
- Planned in the third Phase 2 slice:
  - reject schema variants that are currently ignored silently
  - require at least one text item for scan execution
  - return explicit validation errors when unsupported multimodal/tool fields are present
- Implemented in the third Phase 2 slice:
  - requests without `texts` are now rejected explicitly
  - non-empty unsupported fields are rejected instead of being ignored
  - README now documents the current text-only request contract

## Initiative: Phase 3 — production readiness

Status: validated by Guillaume; delivery in serialized merges after parallel waves.

- Wave 1: L1 LiteLLM contract; L2 runtime/auth.
- Wave 2: L3 policy engine/findings.
- Wave 3: L4 French normalization/PII; L5 native secrets entropy/gitleaks.
- Wave 4: L6 optional HTTP classifier; L7 offline evaluation; L8 container metrics.

- [x] L1: LiteLLM contract compatibility, strict scan routes, metadata and text alignment (merged, PR #4).
- [x] L2: Runtime and authentication (merged, PR #5).
- [x] L3: Policy engine and findings (merged, PR #8).
- [ ] L4: French normalization and PII.
- [ ] L5: Native secrets with entropy/gitleaks.
- [ ] L6: Optional HTTP classifier.
- [ ] L7: Offline evaluation.
- [ ] L8: Container and metrics.

Corrective lots C1 (prompt-injection response scope, PR #6) and C2 (runtime resource bounds,
PR #7) are merged. Main is at `5368afc` (L3).

### Validated split of the remaining lots (a / b)

Lots L4 to L8 are each split in two so that independent cores can be built in parallel and
merged one at a time:

- **a**: independent core in new packages (or new files) with unit tests and a local README or
  ADR when structural. No policy, API or environment wiring, no runtime registration.
- **b**: wiring PR that registers the core in the policy catalog, API and environment contract,
  with integration and end-to-end tests, `.env.template` and root README updates.

| Lot | a | b |
| --- | --- | --- |
| L4 | French normalization and PII core (owns `golang.org/x/text` in `go.mod`/`go.sum`) | policy/API/env wiring |
| L5 | Native secrets core: entropy and gitleaks-style rules (security review required) | policy/API/env wiring |
| L6 | Optional HTTP classifier core | policy/API/env wiring |
| L7 | Offline evaluation core | evaluation CI workflow and wiring |
| L8 | Container image and CI build (delivered, see below) | Metrics, engine and runtime changes |

`plan.md` and the root `README.md` are updated only by the lot designated for it (L8a for the
plan split and statuses) to avoid merge conflicts between parallel cores.

L1 scope: transport DTOs, dedicated contract tests and route documentation. No runtime,
authentication, configuration, maximum-length implementation or production changes.

L1 delivered with separate LiteLLM transport types, upstream payload regression
coverage, strict scan compatibility, and ADR 0005. No environment contract change.

L2 delivered in PR #5 with rune-based text limits, validated transport deadlines and
body limits, optional multi-key authentication, bounded signal shutdown, and ADR
0006. Full local validation and independent security review completed; final CI
validates the branch integrated with L1. No production changes.

## C1: prompt-injection response scope correction

- Validated scope: allow deterministic `prompt_injection` for both request and
  response scanning, including LiteLLM pre-call and post-call.
- Reproduce the response HTTP 400 with a failing local HTTP regression test
  before changing production code; keep unknown scopes invalid.
- Cover clean and injected texts on both HTTP contracts and both scopes.
- Limit production changes to scope support. Diagnose other response limitations
  without expanding this correction. No architecture or environment change.
- Run formatting, all test scopes, pre-commit, dead-code review, independent
  review, and CI; leave an open PR for the orchestrator's real LiteLLM journey.

- Evidence: before the fix, the local HTTP response/injection test returned
  400 with "Guardrail 'prompt_injection' does not support scope 'response'".
  After the one-line support correction, both routes return 200/BLOCKED for
  injections and 200/NONE for clean texts in both scopes; unknown scopes
  still return 422.
- Diagnosis: all other registered deterministic guardrails support response.
  The optional semantic detector remains request-only and is not registered.
- Validation: full Go suite, integration, end-to-end, formatting and pre-commit
  passed with Go 1.26.11, GOMAXPROCS=2 and GOFLAGS=-p=1. Dead-code pass found no
  obsolete production path or import. No environment contract changed, so
  .env.template and local .env need no edits; no structural ADR is required.


## C2 — Runtime resource bounds

Authorized final corrective PR, based on main 6364b043ecac6164bf77854ea3f3514b972e81c8.
- F1: positive concurrency configuration (default 2), admission after auth and
  before body parsing; stable 503/Retry-After, health exemption and deferred release.
- F2: Huma ceiling one byte above the inclusive transport ceiling; real HTTP
  boundary tests on native and LiteLLM APIs with known/chunked lengths.
- F3: safe bounded request IDs, UTF-8 User-Agent log bound, 32 KiB server headers.
- Regression tests written and observed failing before fixes. Preserve strict scan,
  permissive LiteLLM and C1 input/output scopes; no archive, Docker or production work.
- Validate all Go suites and pre-commit, independent review, one open unmerged PR.

## L3 — Policy engine and findings

Validated scope (wave 2, central lot), based on main 6eeac11ada08ad379358cbf93dec4062e67c2a64.
- Shared domain-level engine (`internal/policy`) independent of HTTP and providers;
  typed `Stage`/`Action`/`Mode` enums with explicit parsing.
- Findings `{text_index, detector, type, rule, start, end, score?, action}` with
  rune offsets into the original text (start inclusive, end exclusive), sorted
  deterministically, never carrying values; logs record counts only.
- Named YAML policies (schema version 1, embedded or whole-file override) with
  ordered per-stage chains, block/mask/annotate actions and enforce/detect modes,
  strictly validated at startup; no fallback to another policy.
- Typed masks (`{TYPE}`), deterministic overlap merging that keeps original
  offsets and 1:1 text alignment.
- `POST /v1/guardrails/{policy}` documented in OpenAPI; LiteLLM selection through
  `additional_provider_specific_params.policy` with `LITELLM_DEFAULT_POLICY`
  fallback (legacy `LITELLM_GUARDRAIL_NAME` alias); `/scan/*` reimplemented on the
  engine with unchanged contracts.
- One shared regex detector replaces the detect_pii/detect_secret duplication.
- Out of scope: L4 normalization/French PII/checksums, L5 entropy/gitleaks, L6
  HTTP classifier, Docker, metrics, evaluation CI, `archive/`.
- ADR: `docs/adr/0007-policy-engine-and-findings.md`.

Delivered:
- Engine, schema and catalog in `internal/policy`; detectors in
  `internal/guardrails/regex.go`; embedded `policies.yaml` with the legacy single
  detector policies plus `default` and `audit`; typed pattern rules.
- `/scan/*` and the default LiteLLM policy are guarded by a golden corpus recorded
  from the previous implementation (`tests/end2end/api/testdata/compat_golden.json`).
- Tests: engine and schema unit tests (multi-detector input/output chains, all
  actions in both modes, Unicode typed masks, overlaps, limits, detector errors,
  invalid configurations), integration tests (overrides, startup errors), and
  end-to-end tests (policy route, LiteLLM policy selection, OpenAPI, logs, auth
  and body limits on the new route).
- Environment: `LITELLM_DEFAULT_POLICY` added to `.env.template` and local `.env`.

## L8a — Container image

Scope (validated split of L8): `Dockerfile`, `.dockerignore`, a build-only
`.github/workflows/container.yml`, a root README `Container` section and
`docs/adr/0012-container-image.md`. No Go code, metrics, engine or runtime change.

Delivered:
- Multi-stage build: official `golang` Alpine image matching `go.mod` and a
  `gcr.io/distroless/static-debian13:nonroot` runtime, both pinned by tag and digest.
  `CGO_ENABLED=0`, `-trimpath`, static binary, exec-form `ENTRYPOINT`, uid `65532`.
- Port, configuration, health probe and signal handling documented in the README; no
  `HEALTHCHECK` instruction (no probe binary in distroless).
- CI builds the image on pull requests with `contents: read`, no push and no registry login, and
  checks that the build image matches the `go` directive.
- Evidence: image build through `heavy` on `codex-dev`; smoke test on a loopback port with
  `GET /health/` returning 200, `POST /scan/secrets` and `/scan/prompt-injection` returning JSON
  decisions, non-root process, statically linked binary, CA bundle present and `docker stop`
  exiting 0 in about 0.25 s (graceful `SIGTERM`).
- ADR: `docs/adr/0012-container-image.md`. No environment contract change.
- Remaining for L8b: metrics, engine and runtime changes.

## L4b — Normalized French guardrails

Validated scope: integrate L4a normalization and validators in PII/injection
only, preserve original byte/rune spans and graphemes, add French hostile
instruction rules and correct shed/checksum/version/card-space false positives.
No secrets-core, HTTP classifier, Docker, dependency or transport/admission work.

Implementation:
- Shared detector normalizes PII/injection and maps matches with OriginalBytes.
- Explicit YAML checksum validators; contextual French NIR/SIREN/SIRET types.
- Invalid UTF-8 and replacement characters fail closed (ADR 0013).
- Regression tests were run failing first for all reported bugs; unit fixtures,
  override integration tests, and v1/scan/LiteLLM input/output journeys cover
  original findings, typed masks, detect/annotate and checksums.
- Golden compatibility differs only by removal of the broad tool-listing false
  positive. Environment files unchanged: no new environment contract.
||||||| parent of 9a5d491 (feat: observe policy and detector executions with Prometheus)
## L8b — Prometheus metrics

Validated scope: per-handler injectable registry, authenticated `/metrics` on the
existing listener; minimal transport-independent engine observer for real policy,
limit and per-text detector executions, including clean and error outcomes.
Bound labels to loaded policy/detector names and enums. Preserve API/runtime
contracts. No L4b regex/YAML, L5/L6 wiring, evaluation workflow or archive changes.
Deliver adapter, unit/integration/end-to-end tests, Docker smoke and ADR 0014.
