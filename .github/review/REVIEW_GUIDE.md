# Review Guide

## Goal

Standardize code reviews to cover:

- Correctness and security
- Repository coherence
- Technical debt (dead code, complexity, duplication)
- Contracts (API/CLI/schemas/config)
- Tests and observability

## Layered review method

### Layer A — Intent

- Summarize the change in 1 sentence.
- List impacted invariants (API, schemas, business rules).
- Identify impacted areas (modules, CLI, config, DB, CI).

### Layer B — Correctness & Security

- Failure cases: invalid inputs, nulls, timeouts, retries, pagination, concurrency.
- Security: authn/authz, injections, secrets, SSRF, path traversal, sensitive logs.
- Observability: structured logs, actionable errors, metrics if critical path.

### Layer C — Repository Coherence

- Conventions (naming, structure, exceptions, types).
- Existing patterns vs new “one-off”.
- Logic duplication.
- Docs/config/schemas aligned with code.

### Layer D — Debt & Maintainability

- Dead code / unreachable branches / obsolete flags.
- Refactoring opportunities.
- Complexity reduction.
- Tests targeting behavior.

## Severity levels

- High: bug, security issue, contract break, critical debt.
- Medium: incoherence, duplication, avoidable complexity, missing tests.
- Low: style, naming, micro-optimizations.

## Expected review output

- List of findings classified (High/Med/Low).
- Minimal fix proposals for High/Med.
- Explicit regression risk assessment.
