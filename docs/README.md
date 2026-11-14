# Documentation

Reference pages:

- [`api.md`](./api.md): routes, request/response contracts, policies, LiteLLM integration
- [`operations.md`](./operations.md): configuration, container image, logging, metrics
- [`detectors.md`](./detectors.md): deterministic detectors and the optional semantic detector
- [`evaluation.md`](./evaluation.md): offline regression gate, corpora and results

Process tracks:

- [`engineering/`](./engineering/README.md): delivery standards and review workflow
- [`adr/`](./adr/README.md): architecture decision records for long-term technical choices

## Usage

- Start from engineering guardrails before implementation and review.
- Create or update an ADR whenever architecture or structure decisions change.
- Keep migration decisions explicit when porting behavior from `archive/`.
