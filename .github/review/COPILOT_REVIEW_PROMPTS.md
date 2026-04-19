# Copilot Review Prompts

## Pass 1 — Findings only (no code proposals)

- "Do a review focused on repo coherence, dead code, refactoring, contracts."
- "List only findings, classified by severity (High/Med/Low)."
- "Compare this patch to existing patterns in the repo."
- "List what becomes potentially dead or unused."
- "Identify duplications or internal API inconsistencies."

## Pass 2 — Minimal fixes

- "For each High/Med item, propose a minimal fix (smallest possible diff)."
- "Indicate regression risk for each proposal."
- "Propose an alternative if the refactor is too risky for this PR."

## Targeted prompts

### Coherence

- "Which repo conventions are violated by this patch?"
- "What minimal refactor aligns this code with existing style?"

### Dead Code

- "Which symbols become unreferenced after this change?"
- "Which branches/functions are now unreachable?"

### Refactoring

- "Detect potential duplications in the repo related to this change."
- "Propose 2 options: micro-refactor vs shared abstraction."

### Contracts

- "Which public contracts change (API/CLI/config/schemas)?"
- "Is there a silent behavioral breaking change?"

### Tests

- "Which essential tests are missing to cover behavior?"
- "Which existing tests are too coupled to the implementation?"
