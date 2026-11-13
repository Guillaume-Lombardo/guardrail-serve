"""Start the real server with a fake backend for black-box (Go) tests.

Prints `LISTENING <port>` on stdout once the socket is bound and ready.
Settings come from the SIDECAR_* environment, exactly like production.
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

from fake_backend import FakeBackend  # noqa: E402
from sidecar.config import Config  # noqa: E402
from sidecar.server import Application, BoundedServer  # noqa: E402


def main() -> None:
    config = Config.from_env()
    app = Application(config)
    app.set_backend(FakeBackend(delay=float(os.environ.get("FAKE_DELAY_SECONDS", "0"))))
    server = BoundedServer((config.host, config.port), app)
    print(f"LISTENING {server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
