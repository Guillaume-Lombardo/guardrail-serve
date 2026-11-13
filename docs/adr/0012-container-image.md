# 0012 - Container image

## Context

The service is a single static Go binary whose default policies and patterns are embedded
(`internal/resources/defaults`). It is configured only through environment variables, writes
nothing to disk and already handles `SIGTERM` with a bounded graceful shutdown (ADR 0006). The
Phase 3 plan asks for a small, reproducible container image delivered separately from metrics and
runtime changes, with a CI job that proves the image builds without publishing it.

Constraints: no new Go dependency, no Go code change, no registry credentials in CI, and a build
that does not depend on mutable image tags.

## Decision

- **Multi-stage `Dockerfile`**. The build stage uses the official `golang` Alpine image and the
  runtime stage `gcr.io/distroless/static-debian13:nonroot`.
- **Pinned bases**. Both images are referenced by tag and manifest-list digest. The build image
  tag must match the `go` directive of `go.mod`; the container workflow fails otherwise.
  `GOTOOLCHAIN=local` prevents silent toolchain downloads during the build. Bumping a pin is a
  deliberate, reviewed change (a dependency-update bot can maintain the digests later).
- **Static, reproducible binary**. `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`,
  `-ldflags="-s -w"` and `-mod=readonly` with `go mod verify`. No VCS metadata or local paths end
  up in the binary.
- **Least privilege runtime**. Distroless provides CA certificates and tzdata, no shell, and the
  predefined `65532:65532` user. The binary lives in `/app`, root-owned and read-only for that
  user. `GUARDRAILS_CONFIG_DIR`, when used, is mounted read-only by the operator.
- **Signals and health**. The exec-form `ENTRYPOINT` makes the service PID 1 so it receives
  `SIGTERM` directly. There is no `HEALTHCHECK` because the image has no probe binary; adding one
  would require code or a non-distroless base. Operators probe `GET /health/` from the
  orchestrator. A dedicated probe subcommand is a possible follow-up in the runtime lot.
- **Minimal context**. `.dockerignore` excludes `.git`, `.agent-tmp`, `archive/`, `.env*`, key
  material, tests, docs, skills, workflows and Markdown files, so the context is in practice
  `go.mod`, `go.sum`, `cmd/`, `internal/` and `LICENSE`. Embedded resources live under
  `internal/`, so they are preserved. The `Dockerfile` copies only `go.mod`, `go.sum`, `cmd/`
  and `internal/` into the build stage.
- **CI**. `.github/workflows/container.yml` is disjoint from `ci.yml` and the release workflow.
  It runs with `contents: read`, builds the image with `docker build` and never pushes or logs in
  to a registry. It is not a replacement for any existing check.

## Alternatives considered

- `scratch` runtime: smaller but without CA certificates, tzdata or a non-root user unless
  copied by hand.
- Alpine or Debian slim runtime: shell and package manager enlarge the attack surface for no
  benefit to a static binary.
- Mutable tags only (`golang:1.26`): simpler, but the build is not reproducible and silently
  changes with upstream pushes.
- `HEALTHCHECK` via a Go subcommand: needs a code change, which belongs to the runtime lot.
- Publishing from CI: needs registry credentials and a release policy; out of scope.

## Consequences

- Positives: small (~17 MB), non-root, static image; deterministic base selection; no secret or
  credential required by CI; shutdown behaviour of ADR 0006 is preserved in containers.
- Negatives: digests must be refreshed periodically; no in-image health probe; debugging needs an
  ephemeral debug container because there is no shell.
- Risks: a stale pinned base may miss security fixes until bumped; an operator stop grace period
  shorter than `HTTP_SHUTDOWN_TIMEOUT` truncates the drain (documented in the README).
