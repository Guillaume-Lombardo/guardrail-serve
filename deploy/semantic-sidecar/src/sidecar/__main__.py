"""Entry point: `python -m sidecar [serve|healthcheck]`."""

from __future__ import annotations

import signal
import sys
import threading
import urllib.error
import urllib.request
from typing import Callable

from .backend import Backend, TransformersBackend
from .config import Config, ConfigError
from .server import Application, BoundedServer, load_backend_async


def serve(
    backend_factory: Callable[[Config], Backend] | None = None,
    on_ready: Callable[[int], None] | None = None,
) -> int:
    """Run the server until SIGTERM/SIGINT or a model load failure.

    `backend_factory` and `on_ready` exist so tests can run this exact code path,
    signal handling included, with a fake backend. Production passes neither.
    """
    try:
        config = Config.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    app = Application(config)
    server = BoundedServer((config.host, config.port), app)

    def initiate_shutdown() -> None:
        app.begin_drain()  # admission stops first; the accept loop ends right after
        server.shutdown()

    def stop(_signum: int, _frame: object) -> None:
        # Not done in the handler itself: it interrupts the thread that runs serve_forever.
        threading.Thread(target=initiate_shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    app.log("listening", host=config.host, port=server.server_address[1], model=config.model_label)
    def make_backend() -> Backend:
        if backend_factory is not None:
            return backend_factory(config)
        return TransformersBackend(
            model_id=config.model_id, revision=config.model_revision, model_path=config.model_path,
            labels=config.malicious_labels, batch_size=config.batch_size, max_tokens=config.max_tokens,
            threads=config.torch_threads, verify_labels=config.verify_labels,
        )

    port = server.server_address[1]
    load_backend_async(app, server, make_backend, (lambda: on_ready(port)) if on_ready else None)
    try:
        server.serve_forever()
    finally:
        app.begin_drain()
        server.server_close()  # the listening socket is closed: no new connection is accepted
        app.log("stopped_accepting", active=app.active)
        remaining = app.wait_idle(config.shutdown_grace)
        if remaining:
            # Bounded on purpose: handler threads are daemons, so exiting ends them. An
            # unbounded join could outlive Docker's stop_grace_period and be killed anyway.
            app.log("drain_timeout", remaining=remaining, grace_seconds=config.shutdown_grace)
        else:
            app.log("drained", remaining=0)
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
