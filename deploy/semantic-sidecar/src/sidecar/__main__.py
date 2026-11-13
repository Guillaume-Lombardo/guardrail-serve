"""Entry point: `python -m sidecar [serve|healthcheck]`."""

from __future__ import annotations

import signal
import sys
import threading
import urllib.error
import urllib.request

from .backend import TransformersBackend
from .config import Config, ConfigError
from .server import Application, BoundedServer, load_backend_async


def serve() -> int:
    try:
        config = Config.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    app = Application(config)
    server = BoundedServer((config.host, config.port), app)

    def stop(_signum: int, _frame: object) -> None:
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    app.log("listening", host=config.host, port=server.server_address[1], model=config.model_label)
    load_backend_async(
        app, server,
        lambda: TransformersBackend(
            model_id=config.model_id, revision=config.model_revision, model_path=config.model_path,
            labels=config.malicious_labels, batch_size=config.batch_size, max_tokens=config.max_tokens,
            threads=config.torch_threads,
        ),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 1 if app.load_failed else 0


def healthcheck() -> int:
    try:
        port = Config.from_env().port
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz", timeout=3) as response:  # noqa: S310
            return 0 if response.status == 200 else 1
    except (ConfigError, urllib.error.URLError, OSError):
        return 1


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if command == "serve":
        sys.exit(serve())
    if command == "healthcheck":
        sys.exit(healthcheck())
    print("usage: python -m sidecar [serve|healthcheck]", file=sys.stderr)
    sys.exit(2)
