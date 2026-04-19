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
