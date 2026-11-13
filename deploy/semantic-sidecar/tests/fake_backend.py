"""Deterministic backend for tests. It must never be copied into the image."""

from __future__ import annotations

import time
from typing import Callable, Sequence

from sidecar.backend import DeadlineExceeded, TextTooLong

TRIGGER = "ignore previous instructions"


class FakeBackend:
    """One 'token' per character; attack when the trigger phrase appears."""

    def __init__(self, delay: float = 0.0, scorer: Callable[[str], float] | None = None,
                 post: Callable[[list[float]], list[float]] | None = None) -> None:
        self.delay = delay
        self.scorer = scorer or (lambda text: 0.99 if TRIGGER in text.lower() else 0.01)
        self.post = post
        self.calls = 0

    def score(self, texts: Sequence[str], *, max_tokens: int, deadline: float) -> list[float]:
        self.calls += 1
        for index, text in enumerate(texts):
            if len(text) + 2 > max_tokens:
                raise TextTooLong(index)
        if self.delay:
            time.sleep(self.delay)
        if time.monotonic() >= deadline:
            raise DeadlineExceeded
        scores = [self.scorer(text) for text in texts]
        return self.post(scores) if self.post else scores
