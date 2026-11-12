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
independent of the downstream decoder. Positive server read/write/idle deadlines
bound network operations; invalid environment settings reject startup. Zero runtime
fields in programmatic configurations use safe defaults for existing callers.

The executable owns signal registration; the app owns draining with a fresh,
bounded shutdown context and force-closes remaining connections on expiry.
Text limits remain in the domain guardrail and count runes rather than bytes.

## Consequences
No new dependency or change to HTTP schema ownership is required. Buffering costs
up to one request-body limit per concurrent authenticated request. Keys can rotate
by temporarily configuring old and new keys together; changes require a restart.
WriteTimeout bounds socket writes, not CPU execution; handlers must continue to
respect request contexts for cancellation. TLS and aggregate concurrency limits
remain responsibilities of the ingress/deployment.
