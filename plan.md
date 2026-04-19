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

- Status: `in_progress`
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

- [ ] `gofmt -w .`
- [ ] `go test ./...`
- [ ] `go test ./tests/integration/...`
- [ ] `go test ./tests/end2end/...`
- [ ] `pre-commit run --all-files`

#### Notes / Decisions

- Decision: Start with deterministic regex-based and size-based guardrails in-process, and keep embeddings/LLM as optional future adapters.
- Rationale: This matches the user goal of speed, determinism, and small deployment images while preserving a path for richer guardrails later.
- Follow-up: Extend the service with optional embedding-backed and LLM-backed guardrails on a future dedicated branch.
- GitHub bootstrap: repository created and `main` pushed to `https://github.com/Guillaume-Lombardo/guardrail-serve`.
- ADR record: `docs/adr/0001-go-guardrail-service-foundation.md`
