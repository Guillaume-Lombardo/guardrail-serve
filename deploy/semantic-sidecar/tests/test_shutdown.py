"""Graceful shutdown, tested on a real server process (no Docker, no model).

The process is `tests/run_fake_server.py`, which runs the production
`sidecar.__main__.serve()` (signal handlers included) with a fake backend. The
backend is gated by files, so the tests are deterministic: a request is parked
inside the backend until the test releases it, and SIGTERM is sent while it is
parked. Waits are bounded polls on process output, never fixed sleeps.
"""

from __future__ import annotations

import http.client
import io
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

from fake_backend import FakeBackend  # noqa: E402
from sidecar.config import Config  # noqa: E402
from sidecar.server import Application, BoundedServer  # noqa: E402

SERVER = os.path.join(HERE, "run_fake_server.py")
COMPOSE = os.path.join(HERE, "..", "compose.yaml")
BODY = json.dumps({"texts": ["hello"]}).encode()
HEADERS = {"Content-Type": "application/json"}
WAIT = 15.0


class Process:
    """A running fake server with its stderr events collected in a thread."""

    def __init__(self, **env: str) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.entered = os.path.join(self.tmp.name, "entered")
        self.release = os.path.join(self.tmp.name, "release")
        environment = {
            "SIDECAR_HOST": "127.0.0.1", "SIDECAR_PORT": "0",
            "FAKE_ENTERED_FILE": self.entered, "FAKE_RELEASE_FILE": self.release,
        }
        environment.update(env)
        self.proc = subprocess.Popen(
            [sys.executable, "-I", SERVER], env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        self.events: list[dict] = []
        self._cond = threading.Condition()
        self._reader = threading.Thread(target=self._read_stderr, daemon=True)
        self._reader.start()
        line = self.proc.stdout.readline().strip()
        match = re.fullmatch(r"LISTENING (\d+)", line)
        if not match:
            self.close()
            raise AssertionError(f"unexpected banner {line!r}")
        self.port = int(match.group(1))

    def _read_stderr(self) -> None:
        for line in self.proc.stderr:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            with self._cond:
                self.events.append(event)
                self._cond.notify_all()

    def wait_event(self, name: str, timeout: float = WAIT) -> dict:
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                for event in self.events:
                    if event.get("event") == name:
                        return event
                left = deadline - time.monotonic()
                if left <= 0:
                    raise AssertionError(f"no {name!r} event; got {[e.get('event') for e in self.events]}")
                self._cond.wait(left)

    def names(self) -> list[str]:
        with self._cond:
            return [str(event.get("event")) for event in self.events]

    def wait_file(self, path: str, timeout: float = WAIT) -> None:
        deadline = time.monotonic() + timeout
        while not os.path.exists(path):
            if time.monotonic() >= deadline:
                raise AssertionError(f"{os.path.basename(path)} never appeared")
            time.sleep(0.005)

    def release_backend(self) -> None:
        with open(self.release, "w"):
            pass

    def connect(self, timeout: float = 10) -> http.client.HTTPConnection:
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        self._reader.join(WAIT)
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is not None:
                stream.close()
        self.tmp.cleanup()


class InFlight:
    """A /classify request sent on its own connection from a thread."""

    def __init__(self, process: Process) -> None:
        self.status: int | None = None
        self.body: dict | None = None
        self.connection_header: str | None = None
        self.error: BaseException | None = None
        self.conn = process.connect(timeout=WAIT)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            self.conn.request("POST", "/classify", body=BODY, headers=HEADERS)
            response = self.conn.getresponse()
            self.status = response.status
            self.connection_header = response.getheader("Connection")
            self.body = json.loads(response.read())
        except BaseException as exc:  # noqa: BLE001 - reported through the assertions
            self.error = exc

    def join(self) -> None:
        self.thread.join(WAIT)
        self.conn.close()
        assert not self.thread.is_alive(), "request did not finish"


class ShutdownTest(unittest.TestCase):
    def start(self, **env: str) -> Process:
        process = Process(**env)
        self.addCleanup(process.close)
        return process

    def exit_code(self, process: Process, timeout: float = WAIT) -> int:
        return process.proc.wait(timeout)

    def test_sigterm_lets_the_in_flight_request_finish_before_exit(self) -> None:
        process = self.start(SIDECAR_SHUTDOWN_GRACE_SECONDS="10", SIDECAR_INFERENCE_TIMEOUT_SECONDS="30")
        request = InFlight(process)
        process.wait_file(process.entered)  # the request is parked inside the backend
        process.proc.send_signal(signal.SIGTERM)

        stopped = process.wait_event("stopped_accepting")
        self.assertEqual(stopped["active"], 1)
        self.assertIsNone(process.proc.poll(), "the server exited while a request was in flight")
        with self.assertRaises(OSError):  # admission is stopped: nobody can connect any more
            socket.create_connection(("127.0.0.1", process.port), timeout=2).close()

        process.release_backend()
        request.join()
        self.assertIsNone(request.error, f"in-flight request was cut: {request.error!r}")
        self.assertEqual(request.status, 200)
        self.assertEqual(request.body, {"scores": [0.01]})
        self.assertEqual(request.connection_header, "close")
        self.assertEqual(self.exit_code(process), 0)
        self.assertEqual(process.wait_event("drained")["remaining"], 0)
        names = process.names()
        self.assertLess(names.index("draining"), names.index("stopped_accepting"))
        self.assertLess(names.index("stopped_accepting"), names.index("drained"))

    def test_idle_keep_alive_connection_is_refused_while_draining(self) -> None:
        process = self.start(SIDECAR_SHUTDOWN_GRACE_SECONDS="10", SIDECAR_INFERENCE_TIMEOUT_SECONDS="30")
        process.release_backend()  # the first request must not park
        idle = process.connect()
        self.addCleanup(idle.close)
        idle.request("POST", "/classify", body=BODY, headers=HEADERS)
        first = idle.getresponse()
        self.assertEqual(first.status, 200)
        first.read()
        os.remove(process.release)  # from now on the backend parks again
        os.remove(process.entered)

        request = InFlight(process)
        process.wait_file(process.entered)
        process.proc.send_signal(signal.SIGTERM)
        process.wait_event("draining")

        idle.request("POST", "/classify", body=BODY, headers=HEADERS)
        refused = idle.getresponse()
        self.assertEqual(refused.status, 503)
        self.assertEqual(json.loads(refused.read()), {"error": "shutting_down"})

        process.release_backend()
        request.join()
        self.assertEqual(request.status, 200)
        self.assertEqual(self.exit_code(process), 0)

    def test_blocked_backend_cannot_hold_the_exit_beyond_the_grace(self) -> None:
        process = self.start(SIDECAR_SHUTDOWN_GRACE_SECONDS="1", SIDECAR_INFERENCE_TIMEOUT_SECONDS="60")
        request = InFlight(process)
        process.wait_file(process.entered)  # parked and never released
        started = time.monotonic()
        process.proc.send_signal(signal.SIGTERM)

        self.assertEqual(self.exit_code(process), 0)
        elapsed = time.monotonic() - started
        self.assertGreaterEqual(elapsed, 0.9, "the drain did not wait for the in-flight request")
        self.assertLess(elapsed, 6.0, "the drain is not bounded by the grace period")
        timeout = process.wait_event("drain_timeout")
        self.assertEqual(timeout["remaining"], 1)
        self.assertNotIn("drained", process.names())
        request.join()
        self.assertIsNone(request.status, "a request that never finished must not look successful")

    def test_idle_server_exits_at_once(self) -> None:
        process = self.start(SIDECAR_SHUTDOWN_GRACE_SECONDS="10")
        started = time.monotonic()
        process.proc.send_signal(signal.SIGTERM)
        self.assertEqual(self.exit_code(process), 0)
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertEqual(process.wait_event("drained")["remaining"], 0)

    def test_sigint_drains_like_sigterm(self) -> None:
        process = self.start(SIDECAR_SHUTDOWN_GRACE_SECONDS="10", SIDECAR_INFERENCE_TIMEOUT_SECONDS="30")
        request = InFlight(process)
        process.wait_file(process.entered)
        process.proc.send_signal(signal.SIGINT)
        process.wait_event("stopped_accepting")
        self.assertIsNone(process.proc.poll())
        process.release_backend()
        request.join()
        self.assertEqual(request.status, 200)
        self.assertEqual(self.exit_code(process), 0)


class SlowClientTest(unittest.TestCase):
    """A client that stalls inside the body is counted as active, and the drain still ends."""

    def test_stalled_body_cannot_hold_the_drain_beyond_the_grace(self) -> None:
        config = Config.from_env({
            "SIDECAR_PORT": "0", "SIDECAR_REQUEST_TIMEOUT_SECONDS": "60", "SIDECAR_SHUTDOWN_GRACE_SECONDS": "1",
        })
        app = Application(config, log=io.StringIO())
        server = BoundedServer(("127.0.0.1", 0), app)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        app.set_backend(FakeBackend())
        sock = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=WAIT)
        self.addCleanup(sock.close)
        sock.sendall(
            b"POST /classify HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
            b"Content-Length: 100\r\n\r\n" + b'{"texts"'  # the rest of the body never comes
        )
        deadline = time.monotonic() + WAIT
        while app.active != 1:  # the handler is now blocked reading the body
            self.assertLess(time.monotonic(), deadline, "the handler never became active")
            time.sleep(0.005)

        app.begin_drain()
        server.shutdown()
        server.server_close()
        started = time.monotonic()
        remaining = app.wait_idle(config.shutdown_grace)
        elapsed = time.monotonic() - started
        self.assertEqual(remaining, 1)
        self.assertGreaterEqual(elapsed, 0.9)
        self.assertLess(elapsed, 5.0)


class GraceConfigTest(unittest.TestCase):
    def test_default_grace_covers_the_default_inference_deadline(self) -> None:
        config = Config.from_env({})
        self.assertGreater(config.shutdown_grace, config.inference_timeout)

    def test_grace_is_validated(self) -> None:
        self.assertEqual(Config.from_env({"SIDECAR_SHUTDOWN_GRACE_SECONDS": "3"}).shutdown_grace, 3.0)
        for bad in ("0", "-1", "nan", "inf", "601", "soon"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                Config.from_env({"SIDECAR_SHUTDOWN_GRACE_SECONDS": bad})

    def test_compose_stop_grace_period_exceeds_the_drain_bound(self) -> None:
        with open(COMPOSE, encoding="utf-8") as handle:
            text = handle.read()
        stop = re.search(r"^\s+stop_grace_period:\s*(\d+)s\s*$", text, re.MULTILINE)
        self.assertIsNotNone(stop, "the sidecar service must set stop_grace_period")
        grace = re.search(r"SIDECAR_SHUTDOWN_GRACE_SECONDS:\s*\$\{[^}:-]+:-(\d+)\}", text)
        self.assertIsNotNone(grace, "the compose file must pass SIDECAR_SHUTDOWN_GRACE_SECONDS")
        self.assertGreater(int(stop.group(1)), int(grace.group(1)))
        self.assertGreaterEqual(int(grace.group(1)), Config.from_env({}).inference_timeout)


if __name__ == "__main__":
    unittest.main()
