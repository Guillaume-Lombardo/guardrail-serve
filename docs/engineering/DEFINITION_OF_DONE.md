# Definition of Done (DoD)

A PR is mergeable if:

- All tests pass in CI.
- New behavior is covered by tests.
- Public contracts (API/CLI/schemas/config) are documented.
- No dead code or obvious duplication without justification.
- Logs/errors are actionable and safe.
- Any introduced debt is explicitly documented (issue or referenced TODO).

## Exceptions

- An exception must be justified in the PR.
- A follow-up issue must be created for accepted debt.
