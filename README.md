# guardrail-serve

Native Go service for serving LLM guardrails.

## Status

This repository is migrating from the archived Python reference implementation in `archive/bdf-guardrails` to a native Go implementation focused on lower latency, smaller images, and clearer operational boundaries.

`archive/` is reference material only and must never be committed as part of active delivery work.

## Current Target

The first Go implementation serves deterministic guardrails on:

- `/scan/secrets`
- `/scan/pii`
- `/scan/prompt-injection`
- `/beta/litellm_basic_guardrail_api`

The decision contract is:

- `NONE`
- `BLOCKED`
- `GUARDRAIL_INTERVENED`

## Development Workflow

```bash
gofmt -w .
go test ./...
go test ./tests/integration/...
go test ./tests/end2end/...
pre-commit run --all-files
```

## Project Layout

- `cmd/guardrail-serve`: application entrypoint
- `internal/app`: application wiring and HTTP server bootstrap
- `internal/domain`: guardrail contracts and core behaviors
- `internal/guardrails`: built-in guardrail implementations
- `internal/httpapi`: HTTP handlers, routes, request/response schemas
- `internal/config`: environment and runtime configuration
- `internal/resources`: embedded YAML rule sets and loading helpers
- `tests`: unit, integration, and end-to-end coverage
- `docs`: engineering guides and ADR records (`docs/README.md`)
- `skills`: AI helper skills for coding workflows
- `agent.md`: AI agent role, principles, and delivery contract
- `AGENTS.md`: operational guardrails and pre-PR checklist
- `plan.md`: collaborative planning workspace
- `SKILLS.md`: index of local skills and when to apply them

## GitHub Bootstrap

1. Initialize local git history.
2. Create or connect the GitHub repository.
3. Push the initial `main` branch.
4. After bootstrap, do all further work on dedicated branches with PRs, CI, and review.
