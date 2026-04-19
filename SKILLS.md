# SKILLS.md

## Purpose

This file maps project delivery skills to the active collaborative plan in `plan.md` and clarifies when each skill should be applied.

## Core Skills (Project Local)

- `skills/architecture/SKILL.md`
  - Use for module boundaries, interfaces, transport separation, and ADR-backed architecture decisions.
- `skills/testing/SKILL.md`
  - Use for test strategy across unit, integration, and end-to-end scopes and for migration regression tests.
- `skills/code-style/SKILL.md`
  - Use for Go style, naming, typing discipline, schema clarity, and config/model conventions.
- `skills/tooling/SKILL.md`
  - Use for local tooling workflow (`go`, `gofmt`, `pre-commit`) and dev setup reliability.
- `skills/review-followup/SKILL.md`
  - Use to close review comments and ensure PR feedback is fully addressed.
- `skills/release/SKILL.md`
  - Use when the repository is ready for tagged release packaging and image publication work.

## Skill Usage by Plan

- Use `plan.md` as the source of truth for the current initiative.
- Select the smallest set of skills that covers the validated scope.
- Revisit skill selection when scope changes during user feedback.

## Operating Rules

- Prefer the smallest skill set that fully covers the task.
- Keep artifacts in English by default (French as complementary only if needed).
- Update this file if new project-local skills are added or if plan ownership changes significantly.
- Before implementation/review completion, read and apply:
  - `docs/engineering/DEFINITION_OF_DONE.md`
  - `docs/engineering/REVIEW_RUNBOOK.md`
  - `docs/adr/README.md`
- For every PR, poll CI and review status every 60 seconds and act on relevant findings.
- Never include files from `archive/` in commit scope.
