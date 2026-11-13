# syntax=docker/dockerfile:1.7

# CPU prompt-injection classifier sidecar (ADR 0019, ADR 0020). The model is downloaded
# at build time at a pinned commit and baked into the image: no network access and no
# Hugging Face token at runtime. Python base pinned by tag and digest.
#
# Built with Llama. The default model, meta-llama/Llama-Prompt-Guard-2-86M, is gated and
# published under the Llama 4 Community License. An image that contains its weights is a
# distribution of Llama Materials: keep its LICENSE, USE_POLICY and NOTICE files (copied
# below) and read docs/adr/0020-llama-prompt-guard-2.md before sharing it.
ARG PYTHON_IMAGE=python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

FROM ${PYTHON_IMAGE} AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Hash-pinned install: pip refuses anything not listed in requirements.txt.
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --only-binary=:all: --no-deps -r /tmp/requirements.txt

# Model identity is explicit. Default: Llama Prompt Guard 2 86M (gated: a build needs a
# Hugging Face token with access, passed as a BuildKit secret). Revision must be a full
# commit hash, never a branch. Other pinned models: profiles/*.env.
ARG MODEL_ID=meta-llama/Llama-Prompt-Guard-2-86M
ARG MODEL_REVISION=a8ded8e697ce7c355e395a0df51f94adb4a2fd27
ARG MODEL_SAFETENSORS_SHA256=e72017dbbe89c1232dcbc4a74ce0c389db5b468c42afd05850347b2a8c5f6b09

COPY tools/download_model.py /opt/download_model.py
# The optional token is a BuildKit secret file (--secret id=hf_token,...): it is
# not an ARG/ENV, never lands in a layer and is not printed. Public models need none.
# The gated default fails the build (sanitized message) without a token that has access.
RUN --mount=type=secret,id=hf_token,required=false \
    HF_TOKEN_FILE=/run/secrets/hf_token \
    /opt/venv/bin/python /opt/download_model.py "${MODEL_ID}" "${MODEL_REVISION}" /models/model "${MODEL_SAFETENSORS_SHA256}"

FROM ${PYTHON_IMAGE}

ARG MODEL_ID=meta-llama/Llama-Prompt-Guard-2-86M
ARG MODEL_REVISION=a8ded8e697ce7c355e395a0df51f94adb4a2fd27
# Attribution text and license identifiers of the baked model (profiles/*.env override them).
ARG MODEL_NOTICE=notices/llama4.txt
ARG IMAGE_LICENSES="MIT AND LicenseRef-Llama-4-Community-License"
ARG MODEL_ATTRIBUTION="Built with Llama"
LABEL org.opencontainers.image.title="guardrail-serve-semantic-sidecar" \
      org.opencontainers.image.description="CPU prompt-injection classifier sidecar for guardrail-serve" \
      org.opencontainers.image.source="https://github.com/Guillaume-Lombardo/guardrail-serve" \
      org.opencontainers.image.licenses="${IMAGE_LICENSES}" \
      io.guardrail-serve.model.id="${MODEL_ID}" \
      io.guardrail-serve.model.revision="${MODEL_REVISION}" \
      io.guardrail-serve.model.attribution="${MODEL_ATTRIBUTION}"

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
# License files of the model travel with its weights (LICENSE, USE_POLICY in /models/model);
# the attribution notice sits next to them.
COPY ${MODEL_NOTICE} /models/NOTICE
COPY src /app/src

# Non-root, nothing writable: weights and code are root-owned and read-only.
USER 65532:65532
WORKDIR /app
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=3 \
    CMD ["python", "-m", "sidecar", "healthcheck"]

# Exec form: the server is PID 1 and drains in-flight requests on SIGTERM, bounded by
# SIDECAR_SHUTDOWN_GRACE_SECONDS (README, "Shutdown"). Stop it with a timeout above that bound.
ENTRYPOINT ["python", "-m", "sidecar"]
CMD ["serve"]
