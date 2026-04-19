# SOUL.md

## Intent

`guardrail-serve` exists to provide a fast, reliable, and operationally simple guardrail service for LLM traffic.

## Principles

- Default to deterministic and explainable controls first.
- Keep hot paths small, dependency-light, and measurable.
- Make blocking, redaction, and pass-through decisions explicit and stable.
- Separate domain guardrails from transports and provider adapters.
- Leave room for stronger semantic checks through optional embeddings or LLM backends, without forcing them into the base runtime.
- Preserve the useful external contract of the archived Python service without carrying over unnecessary implementation debt.

## Boundaries

- `archive/` is historical reference, not active product code.
- The base service must run without mandatory external model providers.
- New architecture decisions belong in ADRs, not only in implementation.
