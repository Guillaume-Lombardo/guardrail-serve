---
name: architecture
description: Design and evolve the Go service architecture with explicit boundaries, typed contracts, and low coupling. Use when defining module structure or introducing new abstractions.
---

# Architecture Skill

## Purpose

Design a maintainable Go architecture with clear contracts and low coupling.

## Workflow

1. Clarify objective, scope, and constraints first.
2. Define or update typed contracts first (domain types, interfaces, request/response schemas).
3. Choose simple abstractions before adding polymorphism.
4. Decouple domain logic, orchestration, transport, and provider adapters.
5. Record architecture tradeoffs in `plan.md` and `docs/adr/`.

## Mandatory Decisions

- Define thin interfaces where external dependencies are involved.
- Keep one canonical schema per external contract.
- Make compatibility and migration behavior explicit when contracts evolve.
- Keep `archive/` as reference input, not active code.

## Deliverables

- Update interfaces and module boundaries.
- Update plan entries for architecture decisions.
- Create or revise ADRs for durable choices.
