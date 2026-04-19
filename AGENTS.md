# AGENTS.md

## Mission
Build and maintain a robust Go service and library that exposes deterministic and model-assisted guardrails with clear contracts, high code quality, and reliable delivery workflows.

## Current Stage
This repository is in migration from the archived Python reference implementation in `archive/bdf-guardrails` to a native Go implementation.

The active delivery tooling includes:
- agent governance (`agent.md`)
- collaborative planning workspace (`plan.md`)
- reusable project skills (`skills/*`)
- workflow index (`SKILLS.md`)
- project intent (`SOUL.md`)

## Working Rules
- Use English as the default language for README, code comments, docs, ADRs, and core project artifacts.
- Allow French only as a complementary language when useful for collaboration.
- Keep architecture modular and boundaries explicit.
- Keep runtime dependencies explicit, minimal, and configurable.
- Do not couple domain guardrail logic to HTTP, storage, embedding providers, or LLM providers.
- Prefer stdlib-first choices unless an external dependency clearly improves correctness or operational simplicity.
- Prefer typed enumerations for user-facing choices with explicit string conversions and validation.
- Keep APIs versionable and schemas explicit.
- Use `context.Context` on request-scoped and external-boundary code paths.
- Treat `archive/` as read-only migration reference material and never include files from `archive/` in commits.

## Quality Gates
- Unit tests are the default run target.
- Before closing any PR, run all tests from `tests/unit`, `tests/integration`, and `tests/end2end`.
- Add at least one end-to-end test for each major user-visible flow.
- Add integration tests for boundary behavior when relevant.
- When a bug is reported, write a failing test first, then implement the fix.
- Keep deterministic guardrails deterministic in tests: fixed fixtures, no hidden network access, no flaky timing assumptions.

## Delivery Workflow
- Implement each run, phase, and feature in a dedicated branch created for that specific scope.
- Before substantial implementation, run a short planning exchange with the user and write the validated plan in `plan.md`.
- All future work after repository bootstrap must start by creating or switching to a dedicated non-`main` branch.
- Do not develop features directly on the main branch.
- End every run, phase, and feature delivery with a GitHub Pull Request.
- Use PR review and CI as mandatory validation before merge.
- For every created PR, wait for CI completion and review publication before finalizing.
- Poll PR status every 60 seconds (`gh pr checks` + `gh pr view ...reviews/comments`) until:
  - CI is no longer pending, and
  - at least one review is present (or review definitively reports no review for this PR).
- Do not stop polling right after CI success if review is still missing.
- Evaluate review comments for technical relevance; address pertinent comments in code/tests/docs and explicitly justify non-pertinent comments in PR discussion.
- Before each push/PR, run one explicit dead-code pass and remove unused code/paths/imports no longer referenced.
- Before every push/PR, ensure docs/config bootstrap are synchronized with code changes:
  - update `README.md` when API behavior, setup, or workflow changes
  - update `.env.template` when environment variables change
  - update local `.env` accordingly for validation runs
- Before implementation and before merge, review and respect engineering guidance in:
  - `docs/engineering/DEFINITION_OF_DONE.md`
  - `docs/engineering/REVIEW_RUNBOOK.md`
  - `docs/adr/README.md`
- Document architecture decisions in `docs/adr/` whenever a change introduces or modifies a structural/architectural choice.
- Keep test topology explicit under `tests/unit`, `tests/integration`, and `tests/end2end`.

## Pre-PR Checklist
Run locally:
- `gofmt -w .`
- `go test ./...`
- `go test ./tests/integration/...`
- `go test ./tests/end2end/...`
- `pre-commit run --all-files`
- Run a dead-code cleanup pass (remove unused code, stale helpers, and obsolete branches).
- Confirm documentation/config sync:
  - `README.md` updated if behavior changed
  - `.env.template` updated if env contract changed
  - local `.env` updated for manual/e2e validation
  - `docs/adr/*` updated when architecture decisions changed
- Verify `archive/` remains excluded from the commit scope.

## Skills
Project skills live in `skills/`:
- `skills/architecture/SKILL.md`
- `skills/testing/SKILL.md`
- `skills/code-style/SKILL.md`
- `skills/tooling/SKILL.md`
- `skills/review-followup/SKILL.md`
- `skills/release/SKILL.md`
