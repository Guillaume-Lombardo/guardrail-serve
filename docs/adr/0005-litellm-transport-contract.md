# ADR 0005: Separate LiteLLM and strict scan transport contracts

## Status

Accepted

## Context

LiteLLM's evolving Generic Guardrail API includes caller metadata and opaque
multimodal/tool inputs. Sharing the strict scan DTO rejects valid upstream
payloads and exposes internal response names instead of the required action.

## Decision

Keep separate Huma request/response types for the LiteLLM route. Allow unknown
fields only on this route and accept metadata and opaque content without
inspection. Map only texts, scope and request metadata into the domain request;
only texts and scope drive evaluation. Return action, optional blocked_reason
and texts aligned with the input. Reject misaligned results as upstream errors.

The strict scan DTO retains unknown-field rejection and rejects non-empty
unsupported content. Both contracts accept non-empty request_data.

## Alternatives considered

- Relax all routes: loses useful validation for native scan callers.
- Retain the shared response: incompatible with LiteLLM action/reason names.

## Consequences

Transport compatibility evolves independently of the deterministic domain.
Opaque metadata is never promoted into policy, auth or configuration. Accepting
multimodal/tool fields does not provide protection for their contents. The
README and generated OpenAPI document this limitation. Tests cover the exact
upstream request example and independent scan strictness.
