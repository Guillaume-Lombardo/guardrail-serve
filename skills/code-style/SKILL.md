---
name: code-style
description: Apply Go coding standards, readability rules, and contract discipline in this project. Use when writing or reviewing production code.
---

# Code Style Skill

## Purpose

Keep code consistent, typed, and easy to maintain.

## Standards

- Prefer Go stdlib first.
- Keep public interfaces explicit and small.
- Keep functions focused and package responsibilities clear.
- Use domain-oriented names.
- Add comments only when logic is non-obvious.

## Conventions

- Separate domain contracts, config, resources, and HTTP transport.
- Use typed string enums for user-facing choices where helpful.
- Keep output schemas explicit and versionable.
- Prefer constructor functions over global mutable state.
- Use `context.Context` on boundary-facing code paths.

## Static Checks

- Formatting: `gofmt`
- Tests: `go test`

## Commands

- `gofmt -w .`
- `go test ./...`
