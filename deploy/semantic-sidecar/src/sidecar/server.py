"""Bounded HTTP server for the `scores` wire contract.

POST /classify  {"texts": ["..."]}  ->  {"scores": [0.01]}
GET  /healthz   liveness: the process answers.
GET  /readyz    readiness: the model is loaded and warmed up.

Bounds: body size, texts per request, tokens per text (real tokenizer),
requests in flight, open connections, socket timeouts and a per-request
deadline. Logs and error bodies never contain input text, headers or tokens.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
import uuid
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, TextIO
from urllib.parse import urlsplit

from .backend import Backend, DeadlineExceeded, TextTooLong, validate_scores
from .config import Config

CLASSIFY_PATH = "/classify"
_DRAIN_LIMIT = 1 << 20
_DRAIN_SECONDS = 1.0


class Application:
    """Shared state: configuration, readiness and the inference gate."""

    def __init__(self, config: Config, log: TextIO | None = None) -> None:
        self.config = config
        self.backend: Backend | None = None
        self.load_failed = False
        self.inflight = threading.BoundedSemaphore(config.max_inflight)
        self.inference_lock = threading.Lock()
        self._log = log if log is not None else sys.stderr
        self._log_lock = threading.Lock()

    def set_backend(self, backend: Backend) -> None:
        self.backend = backend

    @property
    def ready(self) -> bool:
        return self.backend is not None

    def log(self, event: str, **fields: Any) -> None:
        """One JSON line. Callers pass only fixed, non-sensitive fields."""
        record = {"ts": round(time.time(), 3), "event": event, **fields}
        with self._log_lock:
            self._log.write(json.dumps(record, separators=(",", ":")) + "\n")
            self._log.flush()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "sidecar"
    sys_version = ""
    server: "BoundedServer"
    _unread = 0

    def setup(self) -> None:
        self.timeout = self.server.app.config.request_timeout
        super().setup()

    # --- logging and responses -------------------------------------------------

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        return

    def log_request(self, code: Any = "-", size: Any = "-") -> None:
        return

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        # Raised by the stdlib parser (bad request line, oversized headers...).
        self.close_connection = True
        self._respond(code, {"error": _ERROR_CODES.get(code, "error")})

    def _respond(self, status: int, payload: dict[str, Any], *, texts: int | None = None,
                 headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        fields: dict[str, Any] = {
            "request_id": getattr(self, "_request_id", ""), "method": self.command or "-",
            "path": getattr(self, "_log_path", "-"), "status": status,
            "duration_ms": round((time.monotonic() - getattr(self, "_started", time.monotonic())) * 1000, 1),
        }
        if texts is not None:
            fields["texts"] = texts
        if "error" in payload:
            fields["error"] = payload["error"]
        self.server.app.log("request", **fields)

    def _begin(self) -> str:
        self._started = time.monotonic()
        self._request_id = uuid.uuid4().hex[:12]
        path = urlsplit(self.path).path
        # Only the two fixed routes are ever logged, never client-chosen paths.
        self._log_path = path if path in (CLASSIFY_PATH, "/healthz", "/readyz") else "other"
        return path

    # --- routes ----------------------------------------------------------------

    def do_GET(self) -> None:
        path = self._begin()
        app = self.server.app
        if path == "/healthz":
            self._respond(200, {"status": "ok"})
        elif path == "/readyz":
            if app.ready:
                self._respond(200, {"status": "ready", "model": app.config.model_label})
            else:
                self._respond(503, {"status": "loading"}, headers={"Retry-After": "2"})
        elif path == CLASSIFY_PATH:
            self._respond(405, {"error": "method_not_allowed"}, headers={"Allow": "POST"})
        else:
            self._respond(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = self._begin()
        if path != CLASSIFY_PATH:
            self.close_connection = True
            self._respond(404, {"error": "not_found"})
            return
        self._classify()

    def _method_not_allowed(self) -> None:
        self._begin()
        self.close_connection = True
        self._respond(405, {"error": "method_not_allowed"}, headers={"Allow": "POST"})

    do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _method_not_allowed

    # --- /classify -------------------------------------------------------------

    def _fail(self, status: int, code: str, *, close: bool = True, **extra: Any) -> None:
        self.close_connection = close or self.close_connection
        headers = {"Retry-After": "1"} if status == 503 else None
        self._respond(status, {"error": code, **extra}, headers=headers)
        if self.close_connection and self._unread:
            self._drain()

    def _drain(self) -> None:
        """Briefly discard the unread body so closing does not reset the client
        before it has read this response. Bounded in bytes and in time."""
        remaining = min(self._unread, _DRAIN_LIMIT)
        self._unread = 0
        deadline = time.monotonic() + _DRAIN_SECONDS
        try:
            while remaining > 0 and (left := deadline - time.monotonic()) > 0:
                self.connection.settimeout(left)
                chunk = self.connection.recv(min(remaining, 65536))
                if not chunk:
                    return
                remaining -= len(chunk)
        except OSError:
            return

    def _classify(self) -> None:
        app = self.server.app
        cfg = app.config
        self._unread = 0
        if not app.ready:
            self._fail(503, "not_ready")
            return
        if "Transfer-Encoding" in self.headers:
            self._fail(400, "unsupported_transfer_encoding")
            return
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            self._fail(411, "length_required")
            return
        if not length_header.isascii() or not length_header.isdigit():
            self._fail(400, "invalid_content_length")
            return
        length = int(length_header)
        self._unread = length
        if length > cfg.max_body_bytes:
            self._fail(413, "body_too_large")
            return
        if _media_type(self.headers.get("Content-Type", "")) != "application/json":
            self._fail(415, "unsupported_media_type")
            return
        if not app.inflight.acquire(blocking=False):
            self._fail(503, "overloaded")
            return
        try:
            self._classify_admitted(length)
        finally:
            app.inflight.release()

    def _classify_admitted(self, length: int) -> None:
        app = self.server.app
        cfg = app.config
        deadline = self._started + cfg.inference_timeout
        try:
            raw = self.rfile.read(length)
        except (socket.timeout, TimeoutError):
            self._unread = 0
            self._fail(408, "request_timeout")
            return
        except OSError:
            self.close_connection = True
            return
        self._unread = 0
        if len(raw) != length:
            self._fail(400, "incomplete_body")
            return

        texts, problem = _parse_texts(raw, cfg.max_texts)
        if texts is None:
            self._fail(*problem)
            return

        backend = app.backend
        assert backend is not None
        if not app.inference_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            self._fail(503, "busy", close=False)
            return
        try:
            raw_scores = backend.score(texts, max_tokens=cfg.max_tokens, deadline=deadline)
            if time.monotonic() >= deadline:  # backend-independent: a late answer is a timeout
                raise DeadlineExceeded
            scores = validate_scores(raw_scores, len(texts))
        except TextTooLong as exc:
            self._fail(422, "text_too_long", close=False, index=exc.index)
            return
        except DeadlineExceeded:
            self._fail(504, "timeout", close=False)
            return
        except Exception as exc:  # noqa: BLE001 - class name only; messages may echo input
            app.log("backend_error", request_id=self._request_id, kind=type(exc).__name__)
            self._fail(500, "backend_error", close=False)
            return
        finally:
            app.inference_lock.release()
        self._respond(200, {"scores": scores}, texts=len(texts))


_ERROR_CODES = {
    400: "bad_request", 404: "not_found", 405: "method_not_allowed", 408: "request_timeout",
    411: "length_required", 413: "body_too_large", 414: "uri_too_long", 415: "unsupported_media_type",
    431: "headers_too_large", 501: "not_implemented", 505: "http_version_not_supported",
}


def _media_type(value: str) -> str:
    message = Message()
    message["Content-Type"] = value
    if message.get_content_type() != "application/json":
        return ""
    charset = message.get_param("charset")
    if charset is not None and str(charset).lower() != "utf-8":
        return ""
    return "application/json"


def _reject_constant(_: str) -> Any:
    raise ValueError("non-finite number")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _parse_texts(raw: bytes, max_texts: int) -> tuple[list[str] | None, tuple[int, str]]:
    """Strict request parsing. Returns (texts, (status, error code))."""
    try:
        document = json.loads(
            raw.decode("utf-8"), parse_constant=_reject_constant, object_pairs_hook=_reject_duplicates
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None, (400, "invalid_json")
    if not isinstance(document, dict) or set(document) != {"texts"}:
        return None, (400, "invalid_request")
    texts = document["texts"]
    if not isinstance(texts, list) or not 1 <= len(texts) <= max_texts:
        return None, (400, "invalid_request")
    if not all(isinstance(text, str) for text in texts):
        return None, (400, "invalid_request")
    for text in texts:
        try:
            text.encode("utf-8")  # lone surrogates from JSON escapes cannot be tokenized
        except UnicodeEncodeError:
            return None, (422, "invalid_text")
    return texts, (0, "")


_BUSY_RESPONSE = (
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n"
    b"Content-Length: 22\r\nRetry-After: 1\r\nConnection: close\r\n\r\n"
    b'{"error":"overloaded"}'
)


class BoundedServer(ThreadingHTTPServer):
    """Threaded server that refuses connections beyond max_connections."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], app: Application) -> None:
        self.app = app
        self.request_queue_size = max(16, app.config.max_connections)
        self._slots = threading.BoundedSemaphore(app.config.max_connections)
        super().__init__(address, Handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.settimeout(1.0)
                request.sendall(_BUSY_RESPONSE)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        # The default prints a traceback (and client address) to stderr.
        exc = sys.exc_info()[1]
        self.app.log("connection_error", kind=type(exc).__name__)


def load_backend_async(app: Application, server: BoundedServer, factory: Callable[[], Backend]) -> threading.Thread:
    """Load the model off the serving thread; shut the server down if it fails."""

    def run() -> None:
        started = time.monotonic()
        try:
            app.set_backend(factory())
        except BaseException as exc:  # noqa: BLE001 - never log the message (paths, labels)
            app.log("model_load_failed", kind=type(exc).__name__)
            app.load_failed = True
            server.shutdown()
            return
        app.log("model_ready", model=app.config.model_label, seconds=round(time.monotonic() - started, 1))

    thread = threading.Thread(target=run, name="model-loader", daemon=True)
    thread.start()
    return thread
