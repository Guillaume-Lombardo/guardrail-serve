# Summary

<!-- 1–3 lines describing the change -->

## Intent and invariants

- Intent:
- Impacted invariants:

## Impacted areas

- Modules:
- CLI / API:
- Config / Schemas / DB:
- CI / Infra:

## Checklist

- [ ] Consistent with repo patterns
- [ ] No dead code introduced
- [ ] No obvious duplication without justification
- [ ] Contracts (API/CLI/config/docs) aligned
- [ ] Tests added or updated (behavior + edge cases)
- [ ] Logs/errors are actionable and safe

## Risks and rollback

- Known risks:
- Rollback plan:

## Docs/Config sync

- [ ] `README.md` updated (if needed)
- [ ] `.env.template` updated (if needed)

## Validation

- [ ] `uv run ruff format .`
- [ ] `uv run ruff check .`
- [ ] `uv run ty check src tests`
- [ ] `uv run pytest -m unit`
- [ ] `uv run pytest -m integration --no-cov`
- [ ] `uv run pytest -m end2end`
- [ ] `uv run pre-commit run --all-files`

## Notes
