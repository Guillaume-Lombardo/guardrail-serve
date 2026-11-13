"""Deterministic backend for tests. It must never be copied into the image."""

from __future__ import annotations

import os
import time
from typing import Callable, Sequence

from sidecar.backend import DeadlineExceeded, TextTooLong

TRIGGER = "ignore previous instructions"


class FakeBackend:
    """One 'token' per character; attack when the trigger phrase appears."""

    def __init__(self, delay: float = 0.0, scorer: Callable[[str], float] | None = None,
                 post: Callable[[list[float]], list[float]] | None = None,
                 entered_file: str | None = None, release_file: str | None = None) -> None:
        self.delay = delay
        # Deterministic gates for process-level tests: `entered_file` is created when a
        # request reaches the backend; scoring then waits (until the deadline) for
        # `release_file` to exist.
        self.entered_file = entered_file
        self.release_file = release_file
        self.scorer = scorer or (lambda text: 0.99 if TRIGGER in text.lower() else 0.01)
        self.post = post
        self.calls = 0

    def score(self, texts: Sequence[str], *, max_tokens: int, deadline: float) -> list[float]:
        self.calls += 1
        for index, text in enumerate(texts):
            if len(text) + 2 > max_tokens:
                raise TextTooLong(index)
        if self.entered_file:
            with open(self.entered_file, "w"):
                pass
        if self.release_file:
            while not os.path.exists(self.release_file):
                if time.monotonic() >= deadline:
                    raise DeadlineExceeded
                time.sleep(0.005)
        if self.delay:
            time.sleep(self.delay)
        if time.monotonic() >= deadline:
            raise DeadlineExceeded
        scores = [self.scorer(text) for text in texts]
        return self.post(scores) if self.post else scores
