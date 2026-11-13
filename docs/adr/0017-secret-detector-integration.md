# ADR 0017: Native secret detector integration

## Status

Accepted

## Decision

Compose ADR 0009's Scanner in a domain detector, registered by the application
under the existing `detect_secret` name. Normalize native input using ADR 0008,
reject invalid/replacement UTF-8 as in ADR 0013, and use Finding.ByteStart/ByteEnd
with OriginalBytes. Domain Detection consumes bytes; the policy engine projects
original rune offsets and merges overlapping mask ranges. Forward rule, type and
optional entropy score without matched values. Keep native overlap precedence.

Explicit secrets YAML files remain complete legacy replacements, including
empty lists. They match original text as before. Missing overrides use native
sources rather than embedded generic regexes. No new environment options or
runtime dependencies. This preserves operator intent while allowing migration
by removing a legacy override. Native rule names and typed masks change as
recorded in README; transport, policies and metrics contracts remain intact.

## Consequences

Native defaults reduce generic length/hash false positives and expand provider,
context and entropy coverage. They incur the scanner cost and known heuristic
limits documented in internal/secrets/README.md. The synthetic corpus and offline
gate provide regression evidence, not exhaustive recall guarantees. Legacy
operators must remove their override to gain normalization and native detection.

The adapter retains one bounded AWS access-id provider shape as
`compat:aws_access_key_id`, only when a native finding does not already cover
it. The fixed L7b corpus labels the AWS documentation example as a secret;
upstream gitleaks excludes it. Masking this entire provider shape preserves the
existing contract without weakening the gate, editing labels or relaxing
provider allowlists globally. No generic length/base64/hex regex is retained.
