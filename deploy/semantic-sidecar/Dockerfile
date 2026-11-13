# syntax=docker/dockerfile:1.7

# CPU prompt-injection classifier sidecar (ADR 0019). The model is downloaded at
# build time at a pinned commit and baked into the image: no network access and
# no Hugging Face token at runtime. Python base pinned by tag and digest.
ARG PYTHON_IMAGE=python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

FROM ${PYTHON_IMAGE} AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Hash-pinned install: pip refuses anything not listed in requirements.txt.
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --only-binary=:all: --no-deps -r /tmp/requirements.txt

# Model identity is explicit. Defaults: ProtectAI deberta-v3-base-prompt-injection-v2
# (Apache-2.0, not gated). Revision must be a full commit hash, never a branch.
ARG MODEL_ID=protectai/deberta-v3-base-prompt-injection-v2
ARG MODEL_REVISION=90c9989b1a342275dd0d1a95aad283c04e075671
ARG MODEL_SAFETENSORS_SHA256=6521cb8d0ac08148c81464899c424e6148fcc62befa371089fa4061d8b6e0424

COPY tools/download_model.py /opt/download_model.py
# The optional token is a BuildKit secret file (--secret id=hf_token,...): it is
# not an ARG/ENV, never lands in a layer and is not printed. Public models need none.
RUN --mount=type=secret,id=hf_token,required=false \
    HF_TOKEN_FILE=/run/secrets/hf_token \
    /opt/venv/bin/python /opt/download_model.py "${MODEL_ID}" "${MODEL_REVISION}" /models/model "${MODEL_SAFETENSORS_SHA256}"

FROM ${PYTHON_IMAGE}

ARG MODEL_ID=protectai/deberta-v3-base-prompt-injection-v2
ARG MODEL_REVISION=90c9989b1a342275dd0d1a95aad283c04e075671
LABEL org.opencontainers.image.title="guardrail-serve-semantic-sidecar" \
      org.opencontainers.image.description="CPU prompt-injection classifier sidecar for guardrail-serve" \
      org.opencontainers.image.source="https://github.com/Guillaume-Lombardo/guardrail-serve" \
      org.opencontainers.image.licenses="MIT" \
      io.guardrail-serve.model.id="${MODEL_ID}" \
      io.guardrail-serve.model.revision="${MODEL_REVISION}"

# The model identity is also what the server reports and validates labels against.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    HF_HOME=/tmp/hf \
    TOKENIZERS_PARALLELISM=false \
    OMP_NUM_THREADS=2 \
    SIDECAR_HOST=0.0.0.0 \
    SIDECAR_PORT=8080 \
    SIDECAR_MODEL_ID=${MODEL_ID} \
    SIDECAR_MODEL_REVISION=${MODEL_REVISION} \
    SIDECAR_MODEL_PATH=/models/model \
    PATH=/opt/venv/bin:$PATH

COPY --from=build /opt/venv /opt/venv
COPY --from=build /models /models
COPY src /app/src

# Non-root, nothing writable: weights and code are root-owned and read-only.
USER 65532:65532
WORKDIR /app
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=3 \
    CMD ["python", "-m", "sidecar", "healthcheck"]

# Exec form: the server is PID 1 and handles SIGTERM for a graceful shutdown.
ENTRYPOINT ["python", "-m", "sidecar"]
CMD ["serve"]
