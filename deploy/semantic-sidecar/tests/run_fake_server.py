"""Run the real `sidecar.__main__.serve()` (signal handling included) with a fake backend.

Prints `LISTENING <port>` on stdout once the fake backend is installed and the
server is ready. Settings come from the SIDECAR_* environment, exactly like
production; FAKE_DELAY_SECONDS, FAKE_ENTERED_FILE and FAKE_RELEASE_FILE tune the
fake backend (see fake_backend.py).
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

from fake_backend import FakeBackend  # noqa: E402
from sidecar.__main__ import serve  # noqa: E402


def make_backend(_config: object) -> FakeBackend:
    return FakeBackend(
        delay=float(os.environ.get("FAKE_DELAY_SECONDS", "0")),
        entered_file=os.environ.get("FAKE_ENTERED_FILE") or None,
        release_file=os.environ.get("FAKE_RELEASE_FILE") or None,
    )


def announce(port: int) -> None:
    print(f"LISTENING {port}", flush=True)


if __name__ == "__main__":
    sys.exit(serve(make_backend, announce))
