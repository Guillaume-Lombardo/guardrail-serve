# ADR 0009: Native secret detection core

## Status

Accepted

## Context

The current `detect_secret` guardrail runs a configured list of regular
expressions. It covers few provider token formats, has no notion of
contextual secrets (`password = ...`) or of high-entropy strings, and has no
false-positive filtering. Mature detectors exist (detect-secrets, gitleaks),
but the Go service must not depend on a Python sidecar or on a large
scanner library.

Constraints:

- stdlib-only Go; `go.mod` cannot change in this lot;
- regular expressions must be RE2 (Go `regexp`): no lookarounds or
  back-references, and every rule must compile at startup;
- the detector scans untrusted free text (prompts, responses), not files or
  commits;
- results must be deterministic and testable with fixed fixtures;
- findings must report original offsets in runes, and never leak values in
  errors or logs;
- the core must be usable by the policy engine (ADR 0007) later without
  depending on it.

## Decision

Add `internal/secrets`, an autonomous package with an explicit `Config` and a
`Scanner` that returns `Finding` values (source, rule, type, rune and byte
offsets, optional entropy score). It has three sources:

1. **gitleaks rules.** The gitleaks default configuration (MIT) is vendored
   as `internal/secrets/rules/gitleaks.toml`, pinned to v8.30.1 / commit
   `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`, byte for byte below a
   provenance and license header; a test checks the upstream SHA-256. A
   strict TOML subset parser loads it (no TOML dependency) and rejects any
   unknown key or syntax. A native evaluator reproduces the gitleaks
   semantics that matter for text: keyword prefilter, secret group selection,
   entropy thresholds, global and rule allowlists (condition, regex target,
   stopwords) and generic-rule precedence. Path- and commit-scoped criteria
   cannot apply to text: rules that need a path are excluded and listed, and
   path/commit allowlist criteria never match. The inline `gitleaks:allow`
   marker is ignored because it would let untrusted text disable detection.
2. **Keyword assignments**, after the detect-secrets keyword approach
   (Apache-2.0, itself derived from Bandit): one RE2 assignment pattern finds
   `key <op> value` shapes, and Go code classifies keys (keyword groups,
   descriptors, negations, identifiers) and values (placeholders, templates,
   references, length and character-class rules).
3. **High-entropy strings**, after detect-secrets: Shannon entropy with the
   4.5 (base64) and 3.0 (hex) thresholds, the all-digit hex adjustment and
   heuristic filters (UUID, likely identifiers and digests such as git SHAs,
   templated values, sequential strings). Filters that only infer "this is an
   identifier" from the shape are overridden by strong secret context, so a
   key that looks like a hash is still reported when assigned to a secret
   key.

Overlaps are resolved by source rank (gitleaks, keyword, entropy). No
runtime registration, policy wiring or environment configuration is part of
this decision; a later change adapts findings to the domain contracts.

Attribution and licenses of gitleaks, detect-secrets and Bandit are recorded
in the root `NOTICE` file.

## Alternatives considered

- **detect-secrets as a Python sidecar.** Rejected: extra runtime, process
  management and latency, contrary to the native Go migration.
- **Linking the gitleaks library.** Rejected: large dependency tree for a
  file/commit oriented scanner, and `go.mod` is frozen in this lot.
- **trufflehog detectors.** Rejected: AGPL licensing and network
  verification model.
- **Hand-written provider regexes only.** Rejected: unmaintainable coverage;
  the vendored gitleaks rules are a maintained, pinned source.
- **A TOML dependency.** Rejected for this lot (no dependency changes); the
  strict subset parser fails loudly when an upstream refresh uses new syntax.

## Consequences

- Positives:
  - 217 maintained provider rules plus contextual and entropy detection,
    with deterministic results and rune offsets.
  - Upgrading gitleaks rules is a reviewed file replacement with a hash
    check; unsupported fields fail the load instead of changing semantics.
  - No new runtime dependency.
- Negatives:
  - The gitleaks evaluator is a reimplementation and must be re-checked
    against upstream semantics on each refresh.
  - Heuristics (keyword classification, entropy filters) are tuned on a
    representative corpus, not on exhaustive real-world data.
- Risks:
  - False negatives documented in `internal/secrets/README.md` (unquoted
    plain-word passwords, no decoding passes, entropy dilution in long runs,
    zero-width or homoglyph keys before normalization).
  - Regex cost on very large texts is bounded by RE2 linear time but grows
    with the number of rules; request size limits (ADR 0006) remain the
    outer bound.
