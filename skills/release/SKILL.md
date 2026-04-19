---
name: release
description: Prepare and validate the Go service release workflow for tags, binaries, and container images.
---

# Release

## Steps

1. Update the version source of truth used by the service or release workflow.
2. Run the full quality pipeline.
3. Build the service binary with `go build ./cmd/guardrail-serve`.
4. Build and validate the container image when container delivery is in scope.
5. Publish using a GitHub tag such as `vX.Y.Z`.

## Notes

- Keep the release footprint minimal and reproducible.
- Document public contract changes in `README.md`.
- Do not include `archive/` artifacts in release scope.
