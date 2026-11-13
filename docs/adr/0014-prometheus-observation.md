# ADR 0014: Prometheus observation at the application boundary

Status: accepted

## Context

Findings alone cannot count clean detector invocations, failed invocations or
payload limits that prevent the chain from running. Metrics must cover all HTTP
contracts without coupling policy evaluation to Prometheus or HTTP.

## Decision

The engine accepts an optional synchronous, concurrency-safe Observer. A small
value-only Observation reports completion, duration and bounded categories for
one evaluation or detector call. It never carries input, findings or error text.
Detectors count once per text and step, limits once per evaluation; unexecuted
steps do not count. Invalid detector spans count as errors. Existing constructors
remain usable without observation; providers added later use the same engine hook.

The application creates a fresh Prometheus registry and adapter for each handler,
or accepts an explicitly injected registry. Duplicate registrations return errors.
No default registry, process/Go collectors or scrape instrumentation is installed.
The adapter maps policy/detector names against copied startup allowlists and all
other categories against enums; unexpected values collapse to `unknown`.

GET `/metrics` (under API_PREFIX) is registered on the existing mux and passes
through existing authentication, admission, body and server timeout controls.
Only health is exempt. Rejected requests, unknown policies and scrapes do not run
the engine and therefore produce no guardrail execution observations.

## Consequences

Counters represent completed calls, not HTTP traffic or finding totals. Policy
latency includes limits, detectors and output processing; detector latency covers
the call and span validation. Detect mode reports configured step actions but
policy decisions reflect the applied NONE decision. Failed policies have no
applied decision (`none`). Histogram buckets use the client library defaults.

Labels are finite for a loaded configuration. Cardinality still scales with the
operator-controlled policy catalog and detector chains. No label uses rule,
type, match, URL, request ID, key or free user-supplied policy names.

A synchronous hook adds a small cost to evaluations; observers must return
promptly and must not panic. Prometheus collectors supply concurrency safety.
The default deployment exposes no runtime/process metrics; add only explicit
collectors to a caller-owned registry if required.
