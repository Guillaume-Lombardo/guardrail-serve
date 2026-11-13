# syntax=docker/dockerfile:1.7

# Build stage: Go toolchain pinned by tag and digest. The Go minor version must
# match the `go` directive of go.mod (checked by .github/workflows/container.yml).
FROM golang:1.26.11-alpine3.24@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS build

ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly

WORKDIR /src

# Resolve dependencies first so this layer is reused while only sources change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

# Default resources are embedded (internal/resources/defaults), so copying the
# source tree is enough: nothing else is read from disk at runtime.
COPY cmd ./cmd
COPY internal ./internal

# Static, reproducible binary: no cgo, no VCS stamping, no local paths.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -buildvcs=false -ldflags="-s -w" \
      -o /out/guardrail-serve ./cmd/guardrail-serve

# Runtime stage: distroless static ships CA certificates, tzdata and a
# predefined non-root user (uid/gid 65532), with no shell or package manager.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

LABEL org.opencontainers.image.title="guardrail-serve" \
      org.opencontainers.image.description="Deterministic guardrail service for LiteLLM and direct HTTP scans" \
      org.opencontainers.image.source="https://github.com/Guillaume-Lombardo/guardrail-serve" \
      org.opencontainers.image.licenses="MIT"

# The binary stays root-owned and read-only for the non-root runtime user: the
# service writes nothing to disk. Mount GUARDRAILS_CONFIG_DIR read-only if used.
WORKDIR /app
COPY --from=build /out/guardrail-serve /app/guardrail-serve

USER 65532:65532

# API_PORT defaults to 8000. Health: GET /health/ (exempt from API-key auth).
# No HEALTHCHECK instruction: the image has no shell or curl, so probe the HTTP
# endpoint from the orchestrator instead.
EXPOSE 8000

# Exec form: the service is PID 1 and receives SIGTERM/SIGINT directly for its
# graceful shutdown (HTTP_SHUTDOWN_TIMEOUT).
ENTRYPOINT ["/app/guardrail-serve"]
