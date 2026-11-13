# ADR 0006: Runtime transport protections

## Status
Accepted

## Context
The service needs bounded transport resource use, optional shared-key access,
and graceful shutdown without coupling guardrail logic to HTTP authentication.

## Decision
Keep transport middleware in `internal/app`, outside the HTTP contract package.
Authenticate before reading request bodies and before entering request logging.
Hash credentials with SHA-256 and compare all fixed-size digests in constant time.
Reject ambiguous credential headers; exempt only the exact prefixed GET health route.
Authentication is disabled when no keys are configured.

Buffer at most the configured body limit plus one byte before dispatch. This
ensures unknown-length or malformed oversized JSON consistently returns 413,
independent of malformed JSON. Configuration is capped at 1 MiB inclusive; Huma operations use a ceiling
one byte higher so the middleware alone decides the encoded body limit; raising that ceiling requires a coordinated
HTTP contract change. Positive server read/write/idle deadlines
bound network operations; invalid environment settings reject startup. Zero runtime
fields in programmatic configurations use safe defaults for existing callers.

The executable owns signal registration; the app owns draining with a fresh,
bounded shutdown context and force-closes remaining connections on expiry.
Text limits remain in the domain guardrail and count runes rather than bytes.

## Consequences
No new dependency or change to HTTP schema ownership is required. Buffering alone
costs up to one body limit plus one byte per admitted request. Parsing and schema
validation amplify this: malformed 1 MiB arrays measured roughly 120 MiB per
request. This observation is not a proven worst-case memory bound.
A nonblocking semaphore limits concurrent requests after authentication and before
body reading, defaulting to 2 (`HTTP_MAX_CONCURRENT_REQUESTS`, positive integer).
Saturation returns JSON 503 with Retry-After: 1; unauthenticated callers still get
401 first. Deferred release covers returns, panics and handler completion after
cancellation; a canceled handler still executing retains its slot. The exact GET
health route bypasses admission and body buffering. Deployment sizing must reserve
baseline memory, GC and operational headroom beyond the observed ~240 MiB for two
malformed requests. Huma v2.37.3 exposes no validation error-count limit on this
path; changing validation or opaque LiteLLM fields is outside this correction.
Headers are capped at 32 KiB plus net/http's parser allowance. Client request IDs
must match 1–128 ASCII `[A-Za-z0-9._-]` characters, otherwise they are regenerated;
logged User-Agent is truncated to at most 256 valid UTF-8 bytes. Keys can rotate
by temporarily configuring old and new keys together; changes require a restart.
WriteTimeout bounds socket writes, not CPU execution; handlers must continue to
respect request contexts for cancellation. TLS and aggregate connection limits
remain responsibilities of the ingress/deployment.
