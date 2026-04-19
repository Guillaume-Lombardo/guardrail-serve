# Repo Coherence Playbook

## Coherence Checklist

- [ ] Code follows existing patterns (naming, errors, types, config).
- [ ] No new pattern introduced without justification.
- [ ] Internal APIs are consistent across similar modules.
- [ ] Docs and schemas match the code.

## Dead Code Detection

Typical signals:

- Unreferenced functions/classes.
- Unused parameters.
- Unread flags/config.
- Branches that became unreachable.
- Tests covering removed or obsolete code.

Actions:

- Remove dead code if risk is low.
- Otherwise: create a tech-debt issue and document it.

## Duplication / Refactoring Heuristics

- Same logic with different names.
- Repeated sequences (parsing, mapping, HTTP calls, retries, error handling).
- Copy-paste blocks with minor variations.

Options:

- Micro-refactor: extract local helper.
- Repo-level abstraction: shared utility module.

## Decide: keep vs refactor

Keep if:

- Abstraction cost > benefit.
- Code is truly specific and stable.

Refactor if:

- Duplication is likely to grow.
- Bugs/fixes would need propagation to many places.
