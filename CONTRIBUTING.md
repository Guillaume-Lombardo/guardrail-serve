# Contributing to guardrail-serve

## Scope

This repository builds a Go service for serving LLM guardrails with deterministic fast paths first and explicit extension points for embedding- and LLM-based checks later.

`archive/` is migration reference material only and must never be included in commits.

## Prerequisites

- Go 1.24+
- `pre-commit`
- Optional: Docker

## Local setup

```bash
pre-commit install
```

## Development workflow

1. Create a dedicated branch from `main`.
2. Validate scope in `plan.md` before substantial implementation.
3. Implement the change with tests.
4. Keep docs and config in sync when behavior changes:
   - `README.md`
   - `.env.template`
   - `docs/adr/*` when architecture changes
5. Open a Pull Request.

## Quality standards

A change is acceptable if:

- It follows existing repository patterns (naming, structure, config, errors, interfaces).
- It does not introduce dead code or unreachable branches.
- It does not introduce obvious duplication without justification.
- Public contracts (API/config/schema) remain consistent and documented.
- New or changed behavior is covered by tests.
- Logs and errors are actionable and do not leak sensitive data.
- Any accepted technical debt is explicitly documented.
- No file from `archive/` is part of the commit.

## Required checks before PR

```bash
gofmt -w .
go test ./...
go test ./tests/integration/...
go test ./tests/end2end/...
pre-commit run --all-files
```

## Testing policy

- Add unit tests for new logic.
- Add integration tests for supported boundaries and config wiring.
- Add at least one end-to-end test for each main route family.
- For bug fixes, write a failing test first, then implement the fix.
- Prefer tests that validate behavior and invariants rather than internal implementation details.

## Code review expectations

Reviews focus on:

- Correctness and safety.
- Repository coherence.
- Detection and removal of dead code.
- Avoiding or reducing duplication through appropriate factorization.
- Maintainability and test coverage.

Be prepared to justify new abstractions and to split changes if a PR becomes too broad.
