"""Scoring backends. torch and transformers are imported only by TransformersBackend."""

from __future__ import annotations

import math
import time
from typing import Protocol, Sequence


class DeadlineExceeded(Exception):
    """The request deadline passed before scoring finished."""


class TextTooLong(Exception):
    """A text needs more tokens than the configured window."""

    def __init__(self, index: int) -> None:
        super().__init__("text exceeds the token limit")
        self.index = index


class Backend(Protocol):
    def score(self, texts: Sequence[str], *, max_tokens: int, deadline: float) -> list[float]:
        """Return one attack probability per text, in order.

        Raises TextTooLong when a text exceeds max_tokens (tokens counted by the
        real tokenizer, special tokens included) and DeadlineExceeded when
        time.monotonic() passes deadline between micro-batches.
        """


def resolve_label_indices(id2label: dict[int, str], wanted: Sequence[str]) -> list[int]:
    """Map configured malicious labels to class indices, case-insensitively.

    A label missing from the checkpoint, or a set covering every class, is a
    configuration error: silently scoring 0 (or 1) would disable the guardrail.
    """
    by_name: dict[str, int] = {}
    for index, name in id2label.items():
        key = str(name).strip().lower()
        if key in by_name:
            raise ValueError("model labels are ambiguous when compared case-insensitively")
        by_name[key] = int(index)
    indices: list[int] = []
    for label in wanted:
        key = label.strip().lower()
        if key not in by_name:
            known = ", ".join(sorted(str(v) for v in id2label.values()))
            raise ValueError(f"malicious label {label!r} is not a model label (model labels: {known})")
        if by_name[key] not in indices:
            indices.append(by_name[key])
    if not indices:
        raise ValueError("at least one malicious label is required")
    if len(indices) >= len(id2label):
        raise ValueError("malicious labels must not cover every model label")
    return indices


def validate_scores(scores: Sequence[float], expected: int) -> list[float]:
    """Output validation: right count, finite, within [0, 1] (float noise clamped)."""
    if len(scores) != expected:
        raise ValueError("backend returned a wrong number of scores")
    checked: list[float] = []
    for value in scores:
        score = float(value)
        if not math.isfinite(score) or score < -1e-6 or score > 1 + 1e-6:
            raise ValueError("backend returned an invalid score")
        checked.append(min(1.0, max(0.0, score)))
    return checked


class TransformersBackend:
    """Sequence-classification model on CPU through transformers and PyTorch."""

    def __init__(self, *, model_id: str, revision: str, model_path: str, labels: Sequence[str],
                 batch_size: int, max_tokens: int, threads: int) -> None:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self._torch = torch
        if threads > 0:
            torch.set_num_threads(threads)
        local = bool(model_path)
        source = model_path or model_id
        options = {"trust_remote_code": False, "local_files_only": local}
        if not local:
            options["revision"] = revision
        self._tokenizer = AutoTokenizer.from_pretrained(source, use_fast=True, **options)
        if not getattr(self._tokenizer, "is_fast", False):
            raise RuntimeError("a fast tokenizer is required")
        self._model = AutoModelForSequenceClassification.from_pretrained(
            source, use_safetensors=True, **options
        )
        self._model.eval()
        window = getattr(self._model.config, "max_position_embeddings", None)
        if window is not None and max_tokens > window:
            raise RuntimeError("SIDECAR_MAX_TOKENS exceeds the model position window")
        id2label = {int(k): v for k, v in self._model.config.id2label.items()}
        self._malicious = resolve_label_indices(id2label, labels)
        self._pad_id = self._tokenizer.pad_token_id if self._tokenizer.pad_token_id is not None else 0
        self._batch_size = batch_size
        self.score(["warm-up"], max_tokens=max_tokens, deadline=time.monotonic() + 600)

    def score(self, texts: Sequence[str], *, max_tokens: int, deadline: float) -> list[float]:
        torch = self._torch
        encoded = self._tokenizer(
            list(texts), add_special_tokens=True, truncation=False, padding=False,
            return_attention_mask=False,
        )["input_ids"]
        for index, ids in enumerate(encoded):
            if len(ids) > max_tokens:
                raise TextTooLong(index)
        # Shortest first keeps padding small; results are restored to input order.
        order = sorted(range(len(encoded)), key=lambda i: len(encoded[i]))
        scores = [0.0] * len(encoded)
        with torch.inference_mode():
            for start in range(0, len(order), self._batch_size):
                if time.monotonic() >= deadline:
                    raise DeadlineExceeded
                members = order[start:start + self._batch_size]
                width = max(len(encoded[i]) for i in members)
                input_ids = torch.full((len(members), width), self._pad_id, dtype=torch.long)
                mask = torch.zeros((len(members), width), dtype=torch.long)
                for row, i in enumerate(members):
                    length = len(encoded[i])
                    input_ids[row, :length] = torch.tensor(encoded[i], dtype=torch.long)
                    mask[row, :length] = 1
                logits = self._model(input_ids=input_ids, attention_mask=mask).logits
                probabilities = torch.softmax(logits.float(), dim=-1)[:, self._malicious].sum(dim=-1)
                for row, i in enumerate(members):
                    scores[i] = float(probabilities[row])
        return scores
