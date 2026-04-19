# Review Runbook

## 10–15 minute routine

1. Read summary and intent.
2. Identify impacted contracts.
3. Check coherence with the rest of the repo.
4. Look for duplication and dead code.
5. Check tests and observability.
6. Classify findings (High/Med/Low).

## Red flags

- New pattern without justification.
- Duplicated logic.
- Flags/config added but never read.
- No tests for a behavior change.
- Contract change not documented.

## Decide

- Ask for refactor if future cost > immediate cost.
- Otherwise, accept with explicitly tracked debt.
