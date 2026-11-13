"""Environment configuration. Every value is validated; nothing is read lazily."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Mapping

# Default model: ProtectAI deberta-v3-base-prompt-injection-v2 (Apache-2.0, not gated).
# The revision is the commit of the model repository, not a mutable branch.
DEFAULT_MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
DEFAULT_MODEL_REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"
DEFAULT_MALICIOUS_LABELS = ("INJECTION",)

_HEX40 = frozenset("0123456789abcdef")


class ConfigError(ValueError):
    """Invalid configuration. Messages never contain secret values."""


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    model_id: str
    model_revision: str
    model_path: str
    malicious_labels: tuple[str, ...]
    max_body_bytes: int
    max_texts: int
    max_tokens: int
    max_inflight: int
    max_connections: int
    request_timeout: float
    inference_timeout: float
    batch_size: int
    torch_threads: int
    shutdown_grace: float

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env

        def text(name: str, default: str) -> str:
            return env.get(name, default).strip()

        def integer(name: str, default: int, low: int, high: int) -> int:
            raw = env.get(name, "").strip()
            if not raw:
                return default
            try:
                value = int(raw)
            except ValueError:
                raise ConfigError(f"{name} must be an integer") from None
            if not low <= value <= high:
                raise ConfigError(f"{name} must be between {low} and {high}")
            return value

        def seconds(name: str, default: float) -> float:
            raw = env.get(name, "").strip()
            if not raw:
                return default
            try:
                value = float(raw)
            except ValueError:
                raise ConfigError(f"{name} must be a number of seconds") from None
            if not math.isfinite(value) or not 0 < value <= 600:
                raise ConfigError(f"{name} must be in (0, 600]")
            return value

        model_id = text("SIDECAR_MODEL_ID", DEFAULT_MODEL_ID)
        model_path = text("SIDECAR_MODEL_PATH", "")
        is_default = model_id == DEFAULT_MODEL_ID
        revision = text("SIDECAR_MODEL_REVISION", DEFAULT_MODEL_REVISION if is_default else "")
        if not model_id:
            raise ConfigError("SIDECAR_MODEL_ID must not be empty")
        if not model_path and not (len(revision) == 40 and set(revision) <= _HEX40):
            raise ConfigError("SIDECAR_MODEL_REVISION must be a full 40-character lowercase commit hash")

        raw_labels = env.get("SIDECAR_MALICIOUS_LABELS", "").strip()
        if raw_labels:
            labels = tuple(part.strip() for part in raw_labels.split(","))
        elif is_default:
            labels = DEFAULT_MALICIOUS_LABELS
        else:
            raise ConfigError("SIDECAR_MALICIOUS_LABELS is required when SIDECAR_MODEL_ID is not the default model")
        if not labels or any(not label for label in labels):
            raise ConfigError("SIDECAR_MALICIOUS_LABELS must be a comma-separated list of non-empty labels")

        return cls(
            host=text("SIDECAR_HOST", "127.0.0.1"),
            port=integer("SIDECAR_PORT", 8080, 0, 65535),
            model_id=model_id,
            model_revision=revision,
            model_path=model_path,
            malicious_labels=labels,
            max_body_bytes=integer("SIDECAR_MAX_BODY_BYTES", 1 << 20, 1024, 64 << 20),
            max_texts=integer("SIDECAR_MAX_TEXTS", 32, 1, 1024),
            max_tokens=integer("SIDECAR_MAX_TOKENS", 512, 8, 8192),
            max_inflight=integer("SIDECAR_MAX_INFLIGHT", 4, 1, 256),
            max_connections=integer("SIDECAR_MAX_CONNECTIONS", 32, 1, 1024),
            request_timeout=seconds("SIDECAR_REQUEST_TIMEOUT_SECONDS", 10.0),
            inference_timeout=seconds("SIDECAR_INFERENCE_TIMEOUT_SECONDS", 10.0),
            batch_size=integer("SIDECAR_BATCH_SIZE", 8, 1, 256),
            torch_threads=integer("SIDECAR_TORCH_THREADS", 0, 0, 256),
            # Upper bound on how long SIGTERM waits for in-flight requests (see README, "Shutdown").
            shutdown_grace=seconds("SIDECAR_SHUTDOWN_GRACE_SECONDS", 20.0),
        )

    @property
    def model_label(self) -> str:
        """Identifier reported by /readyz: model and short revision, no paths."""
        return f"{self.model_id}@{self.model_revision[:12]}" if self.model_revision else self.model_id
