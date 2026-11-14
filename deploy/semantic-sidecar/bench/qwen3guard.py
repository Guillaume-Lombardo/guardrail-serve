"""Bench only: serve Qwen3Guard-Gen on the real sidecar server (`scores` contract).

Qwen3Guard-Gen is a generative safety model: it writes an assessment such as
"Safety: Unsafe\\nCategories: Jailbreak" instead of returning class logits, so the
stock TransformersBackend (sequence classification) cannot load it. This module
plugs a backend into the unchanged `sidecar.__main__.serve()` (same HTTP contract,
limits, deadline and canary) and is never copied into an image: the bench mounts it
read-only and runs `python /bench/qwen3guard.py`.

Decision (fixed before any measurement, ADR 0023): each text is moderated as the
last user prompt with the model's own chat template, greedy decoding. The output
must parse strictly; the text is an injection if and only if the category list
contains `Jailbreak` (the only category Qwen defines for override attempts, input
only). `Safety: Unsafe` with other categories (PII, violence, ...) is not an
injection. The score is 1.0 or 0.0: the model gives no probability and none is
invented. An output that does not parse is a backend error (HTTP 500), never a
score. Each assessment is logged as labels only (no text, no index).
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from sidecar.backend import TextTooLong, run_in_microbatches, verify_label_mapping  # noqa: E402

# The nine categories of the Qwen3Guard prompt-moderation policy, as written by the model.
CATEGORIES = (
    "Violent",
    "Non-violent Illegal Acts",
    "Sexual Content or Sexual Acts",
    "PII",
    "Suicide & Self-Harm",
    "Unethical Acts",
    "Politically Sensitive Topics",
    "Copyright Violation",
    "Jailbreak",
)
INJECTION_CATEGORY = "Jailbreak"
SAFETY_LINE = re.compile(r"Safety: (Safe|Unsafe|Controversial)")
CATEGORIES_PREFIX = "Categories: "
MAX_NEW_TOKENS = 32


class InvalidAssessment(ValueError):
    """The generated text is not a well-formed Qwen3Guard prompt assessment."""


def parse_assessment(content: str) -> tuple[str, tuple[str, ...]]:
    """Return (safety, categories) or raise InvalidAssessment.

    Accepted: exactly two lines, `Safety: <Safe|Unsafe|Controversial>` then
    `Categories: None` or a comma-separated list of known, distinct categories.
    `Safe` must come with `None`; `Unsafe` must name at least one category.
    """
    lines = content.strip().split("\n")
    if len(lines) != 2:
        raise InvalidAssessment("expected two lines")
    safety_match = SAFETY_LINE.fullmatch(lines[0].strip())
    if safety_match is None:
        raise InvalidAssessment("invalid safety line")
    safety = safety_match.group(1)
    second = lines[1].strip()
    if not second.startswith(CATEGORIES_PREFIX):
        raise InvalidAssessment("invalid categories line")
    listed = second[len(CATEGORIES_PREFIX):].strip()
    if listed == "None":
        categories: tuple[str, ...] = ()
    else:
        parts = tuple(part.strip() for part in listed.split(","))
        if any(part not in CATEGORIES for part in parts) or len(set(parts)) != len(parts):
            raise InvalidAssessment("unknown or repeated category")
        categories = parts
    if safety == "Safe" and categories:
        raise InvalidAssessment("safe assessment with categories")
    if safety == "Unsafe" and not categories:
        raise InvalidAssessment("unsafe assessment without category")
    return safety, categories


def injection_score(content: str) -> tuple[float, str, tuple[str, ...]]:
    """1.0 when the assessment lists Jailbreak, 0.0 otherwise; raises on invalid output."""
    safety, categories = parse_assessment(content)
    return (1.0 if INJECTION_CATEGORY in categories else 0.0), safety, categories


def log_event(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), file=sys.stderr, flush=True)


class Qwen3GuardBackend:
    """Greedy prompt moderation on CPU, one text per forward pass."""

    def __init__(self, *, model_path: str, max_tokens: int, threads: int, verify_labels: bool = True,
                 generate=None, tokenizer=None) -> None:
        if generate is None:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            self._torch = torch
            if threads > 0:
                torch.set_num_threads(threads)
            options = {"trust_remote_code": False, "local_files_only": True}
            tokenizer = AutoTokenizer.from_pretrained(model_path, use_fast=True, **options)
            if not getattr(tokenizer, "is_fast", False):
                raise RuntimeError("a fast tokenizer is required")
            model = AutoModelForCausalLM.from_pretrained(
                model_path, use_safetensors=True, torch_dtype=torch.float32, **options)
            model.eval()

            def generate(ids: list[int]) -> str:
                input_ids = torch.tensor([ids], dtype=torch.long)
                with torch.inference_mode():
                    output = model.generate(
                        input_ids=input_ids, attention_mask=torch.ones_like(input_ids),
                        max_new_tokens=MAX_NEW_TOKENS, do_sample=False,
                        pad_token_id=tokenizer.pad_token_id)
                return tokenizer.decode(output[0][len(ids):].tolist(), skip_special_tokens=True)

        self._tokenizer = tokenizer
        self._generate = generate
        self.score(["warm-up"], max_tokens=max_tokens, deadline=time.monotonic() + 600)
        if verify_labels:
            verify_label_mapping(
                lambda texts: self.score(texts, max_tokens=max_tokens, deadline=time.monotonic() + 600))

    def _encode(self, text: str) -> list[int]:
        prompt = self._tokenizer.apply_chat_template([{"role": "user", "content": text}], tokenize=False)
        return list(self._tokenizer(prompt, add_special_tokens=False)["input_ids"])

    def score(self, texts: Sequence[str], *, max_tokens: int, deadline: float) -> list[float]:
        encoded = [self._encode(text) for text in texts]
        for index, ids in enumerate(encoded):
            if len(ids) > max_tokens:
                raise TextTooLong(index)
        scores = [0.0] * len(encoded)

        def process(members: Sequence[int]) -> None:
            for i in members:
                try:
                    score, safety, categories = injection_score(self._generate(encoded[i]))
                except InvalidAssessment:
                    log_event("qwen3guard_invalid_output")
                    raise
                log_event("qwen3guard_assessment", safety=safety, categories=list(categories))
                scores[i] = score

        run_in_microbatches(list(range(len(encoded))), 1, deadline, process)
        return scores


def make_backend(config) -> Qwen3GuardBackend:
    return Qwen3GuardBackend(model_path=config.model_path, max_tokens=config.max_tokens,
                             threads=config.torch_threads, verify_labels=config.verify_labels)


if __name__ == "__main__":
    from sidecar.__main__ import serve

    sys.exit(serve(make_backend))
