---
name: testing
description: Build and maintain a complete test strategy across unit, integration, and end-to-end scopes for the Go service. Use when implementing, refactoring, or validating behavior.
---

# Testing Skill

## Purpose

Guarantee correctness and regression safety across all test scopes.

## Test Topology

- `tests/unit`: fast default scope for domain logic and helpers
- `tests/integration`: component and config/resource wiring
- `tests/end2end`: full HTTP route behavior

## Workflow

1. Write or update unit tests first.
2. Add integration tests for boundaries and adapters.
3. Add end-to-end tests for user-visible workflows.
4. Run `go test ./...` during iteration.
5. Re-run integration and end-to-end coverage before closing work.

## Commands

- `go test ./...`
- `go test ./tests/integration/...`
- `go test ./tests/end2end/...`

## Quality Rules

- Make tests deterministic with explicit fixtures.
- Keep unit tests free of hidden external dependencies.
- Avoid live network in the base service test suite.
- Preserve behavioral parity for intentionally carried-over API contracts.
