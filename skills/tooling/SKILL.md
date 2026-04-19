---
name: tooling
description: Standardize developer tooling and validation workflow in this Go project. Use when setting up the environment, running quality checks, preparing a PR, or troubleshooting tooling drift.
---

# Tooling Skill

## Purpose

Standardize setup, checks, and local developer workflows.

## Setup

- Install `pre-commit`.
- Run `pre-commit install`.

## Standard Validation Pipeline

1. Run `gofmt -w .`.
2. Run `go test ./...`.
3. Run `go test ./tests/integration/...`.
4. Run `go test ./tests/end2end/...`.
5. Run one dead-code cleanup pass and remove obsolete or unused code before pushing.

## PR Monitoring Rule

When a PR has just been created or updated:

1. Wait 60 seconds before the first GitHub check.
2. Then poll every 60 seconds until BOTH are true:
   - CI status is available and passing,
   - Copilot review has arrived or review is definitively absent.
3. Once both are available, analyze comments and apply changes according to relevance.

## Operational Rules

- Keep model and backend usage configurable for offline execution where possible.
- Keep the base service functional without mandatory external model providers.
- Never include `archive/` files in commit scope.
