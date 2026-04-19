# agent.md

## Role

Pragmatic software agent for the `guardrail-serve` Go migration.

## Objective

Deliver high-quality, maintainable increments for a Go guardrail service and its HTTP/API surface while preserving the functional contract of the archived Python reference where intentionally retained.

## Key Principles

- Keep contracts explicit (API, config, outputs).
- Preserve reproducibility with explicit configuration and embedded defaults.
- Prefer clear boundaries between domain logic, orchestration, and infrastructure adapters.
- Keep tests and docs aligned with behavior.
- Keep deterministic paths fast and dependency-light.
- Design extension points for embedding- and LLM-based guardrails without forcing them into the hot path.

## Collaboration Contract

- Clarify unclear scope before coding critical parts.
- Surface assumptions explicitly when requirements are incomplete.
- Prefer small, testable increments.
- Keep docs, skills, and plan synchronized with implementation.
- Before non-trivial implementation, write the agreed plan in `plan.md`.
- Never commit files from `archive/`; treat them as migration reference only.
- After repository bootstrap, never implement on `main`; all subsequent work must happen on a dedicated feature branch.
- For each PR, monitor CI and review by polling every 60 seconds until:
  - CI is finished (not pending), and
  - at least one review has been posted (or is explicitly absent for this PR).
- Do not stop at CI success when review is still pending.
- Address technically relevant review comments with code/test/doc updates; document rationale when comments are not applicable.
- Always align decisions with `docs/engineering/*` and `docs/adr/*` guidance before considering work done.
- Record architecture decisions in `docs/adr/` when introducing or changing architecture/structure choices.

## Definition Of Done (feature level)

A feature is done only if:

- implementation is complete and typed
- tests exist at relevant levels (unit/integration/end2end as needed)
- format, lint, and test checks pass
- dead code pass is completed and unused code is removed
- docs/plan updates are applied when architecture or behavior changes
- `docs/adr/*` is updated when architecture decisions are introduced or revised
- `README.md` is synchronized with user-facing behavior and commands
- `.env.template` is synchronized with the environment variable contract
- local `.env` is updated for validation before push/PR when relevant
- modified code remains decoupled from transport/provider details
- `archive/` remains excluded from the commit scope

## Non-Goals (for now)

- Do not introduce unrelated features in the same change.
- Do not add hidden runtime dependencies without explicit documentation.
- Do not make LLM or embedding providers mandatory for the base service.
