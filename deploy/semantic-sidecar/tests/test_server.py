import http.client
import io
import json
import os
import socket
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, HERE)

from fake_backend import TRIGGER, FakeBackend  # noqa: E402
from sidecar.backend import DeadlineExceeded, resolve_label_indices, run_in_microbatches, validate_scores  # noqa: E402
from sidecar.config import DEFAULT_MODEL_REVISION, Config, ConfigError  # noqa: E402
from sidecar.server import Application, BoundedServer  # noqa: E402

SECRET_TEXT = "PRIVATE-INPUT-MARKER sk-live-123456"


def make_config(**overrides):
    env = {"SIDECAR_PORT": "0", "SIDECAR_MAX_BODY_BYTES": "4096", "SIDECAR_MAX_TEXTS": "4",
           "SIDECAR_MAX_TOKENS": "64", "SIDECAR_MAX_INFLIGHT": "2", "SIDECAR_MAX_CONNECTIONS": "8",
           "SIDECAR_REQUEST_TIMEOUT_SECONDS": "1", "SIDECAR_INFERENCE_TIMEOUT_SECONDS": "2"}
    env.update(overrides)
    return Config.from_env(env)


class Harness:
    def __init__(self, backend=None, **overrides):
        self.log = io.StringIO()
        self.app = Application(make_config(**overrides), log=self.log)
        if backend is not None:
            self.app.set_backend(backend)
        self.server = BoundedServer(("127.0.0.1", 0), self.app)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            data = response.read()
            return response.status, (json.loads(data) if data else None), response
        finally:
            conn.close()

    def classify(self, payload, headers=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        merged = {"Content-Type": "application/json"}
        merged.update(headers or {})
        return self.request("POST", "/classify", body, merged)


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.h = Harness(FakeBackend())
        self.addCleanup(self.h.close)

    def test_scores_in_order(self):
        status, body, _ = self.h.classify({"texts": ["hello", TRIGGER.upper(), "bye"]})
        self.assertEqual(status, 200)
        self.assertEqual(body, {"scores": [0.01, 0.99, 0.01]})

    def test_health_and_ready(self):
        self.assertEqual(self.h.request("GET", "/healthz")[:2], (200, {"status": "ok"}))
        status, body, _ = self.h.request("GET", "/readyz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ready")
        self.assertIn(DEFAULT_MODEL_REVISION[:12], body["model"])

    def test_not_ready_while_loading(self):
        h = Harness(None)
        self.addCleanup(h.close)
        status, body, resp = h.request("GET", "/readyz")
        self.assertEqual((status, body), (503, {"status": "loading"}))
        self.assertEqual(resp.getheader("Retry-After"), "2")
        self.assertEqual(h.request("GET", "/healthz")[0], 200)
        status, body, _ = h.classify({"texts": ["x"]})
        self.assertEqual((status, body), (503, {"error": "not_ready"}))

    def test_routes_and_methods(self):
        self.assertEqual(self.h.request("GET", "/nope")[0], 404)
        self.assertEqual(self.h.request("GET", "/classify")[0], 405)
        self.assertEqual(self.h.request("PUT", "/classify", b"{}")[0], 405)
        self.assertEqual(self.h.request("POST", "/other", b"{}")[0], 404)

    def test_request_validation(self):
        cases = {
            "not json": (b"{", 400, "invalid_json"),
            "nan": (b'{"texts":[NaN]}', 400, "invalid_json"),
            "duplicate key": (b'{"texts":["a"],"texts":["b"]}', 400, "invalid_json"),
            "bad utf8": (b'{"texts":["\xff"]}', 400, "invalid_json"),
            "array": (b"[]", 400, "invalid_request"),
            "extra key": (json.dumps({"texts": ["a"], "x": 1}).encode(), 400, "invalid_request"),
            "empty list": (b'{"texts":[]}', 400, "invalid_request"),
            "too many": (json.dumps({"texts": ["a"] * 5}).encode(), 400, "invalid_request"),
            "non string": (b'{"texts":["a", 1]}', 400, "invalid_request"),
            "texts not list": (b'{"texts":"a"}', 400, "invalid_request"),
            "lone surrogate": (b'{"texts":["\\ud800"]}', 422, "invalid_text"),
        }
        for name, (body, status, code) in cases.items():
            with self.subTest(name):
                got, payload, _ = self.h.classify(body)
                self.assertEqual((got, payload["error"]), (status, code))

    def test_content_type(self):
        body = json.dumps({"texts": ["a"]}).encode()
        for ctype in ("text/plain", "application/json; charset=latin-1", ""):
            with self.subTest(ctype):
                headers = {"Content-Type": ctype}
                status, _, _ = self.h.request("POST", "/classify", body, headers)
                self.assertEqual(status, 415)
        status, _, _ = self.h.request("POST", "/classify", body, {"Content-Type": "application/json; charset=UTF-8"})
        self.assertEqual(status, 200)

    def test_body_and_length_bounds(self):
        status, body, _ = self.h.classify(b"x" * 5000)
        self.assertEqual((status, body["error"]), (413, "body_too_large"))
        sock = socket.create_connection(("127.0.0.1", self.h.port), timeout=3)
        sock.sendall(b"POST /classify HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n")
        self.assertIn(b" 411 ", sock.recv(4096).split(b"\r\n")[0])
        sock.close()
        sock = socket.create_connection(("127.0.0.1", self.h.port), timeout=3)
        sock.sendall(b"POST /classify HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                     b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        self.assertIn(b" 400 ", sock.recv(4096).split(b"\r\n")[0])
        sock.close()
        status, body, _ = self.h.classify(b'{"texts":["a"]}', {"Content-Length": "abc"})
        self.assertEqual(status, 400)

    def test_truncated_body_is_rejected_after_timeout(self):
        sock = socket.create_connection(("127.0.0.1", self.h.port), timeout=5)
        sock.sendall(b"POST /classify HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                     b"Content-Length: 100\r\n\r\n{")
        started = time.monotonic()
        status_line = sock.recv(4096).split(b"\r\n")[0]
        sock.close()
        self.assertIn(b" 408 ", status_line)
        self.assertLess(time.monotonic() - started, 4)

    def test_token_limit_is_explicit(self):
        status, body, _ = self.h.classify({"texts": ["ok", "x" * 100]})
        self.assertEqual((status, body), (422, {"error": "text_too_long", "index": 1}))

    def test_deadline(self):
        h = Harness(FakeBackend(delay=0.4), SIDECAR_INFERENCE_TIMEOUT_SECONDS="0.2")
        self.addCleanup(h.close)
        status, body, _ = h.classify({"texts": ["a"]})
        self.assertEqual((status, body), (504, {"error": "timeout"}))

    def test_late_answer_is_a_timeout_even_if_the_backend_ignores_the_deadline(self):
        class IgnoresDeadline(FakeBackend):
            def score(self, texts, *, max_tokens, deadline):
                time.sleep(0.3)
                return [0.01] * len(texts)

        h = Harness(IgnoresDeadline(), SIDECAR_INFERENCE_TIMEOUT_SECONDS="0.2")
        self.addCleanup(h.close)
        status, body, _ = h.classify({"texts": ["a"]})
        self.assertEqual((status, body), (504, {"error": "timeout"}))

    def test_busy_when_inference_is_occupied(self):
        h = Harness(FakeBackend(delay=1.0), SIDECAR_INFERENCE_TIMEOUT_SECONDS="0.3")
        self.addCleanup(h.close)
        holder = threading.Thread(target=h.classify, args=({"texts": ["a"]},))
        holder.start()
        time.sleep(0.1)
        status, body, resp = h.classify({"texts": ["b"]})
        holder.join()
        self.assertEqual((status, body), (503, {"error": "busy"}))
        self.assertEqual(resp.getheader("Retry-After"), "1")

    def test_inflight_limit(self):
        h = Harness(FakeBackend(delay=0.6), SIDECAR_MAX_INFLIGHT="1", SIDECAR_INFERENCE_TIMEOUT_SECONDS="5")
        self.addCleanup(h.close)
        results = []
        first = threading.Thread(target=lambda: results.append(h.classify({"texts": ["a"]})[0]))
        first.start()
        time.sleep(0.15)
        status, body, _ = h.classify({"texts": ["b"]})
        first.join()
        self.assertEqual((status, body), (503, {"error": "overloaded"}))
        self.assertEqual(results, [200])

    def test_connection_cap(self):
        h = Harness(FakeBackend(), SIDECAR_MAX_CONNECTIONS="1", SIDECAR_REQUEST_TIMEOUT_SECONDS="5")
        self.addCleanup(h.close)
        idle = socket.create_connection(("127.0.0.1", h.port), timeout=3)
        time.sleep(0.2)
        second = socket.create_connection(("127.0.0.1", h.port), timeout=3)
        second.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        data = second.recv(4096)
        self.assertIn(b" 503 ", data.split(b"\r\n")[0])
        self.assertIn(b"overloaded", data)
        idle.close()
        second.close()

    def test_output_validation(self):
        for name, post in {
            "above one": lambda s: [1.5] * len(s),
            "negative": lambda s: [-0.5] * len(s),
            "nan": lambda s: [float("nan")] * len(s),
            "wrong count": lambda s: s[:-1] if len(s) > 1 else [0.1, 0.2],
        }.items():
            with self.subTest(name):
                h = Harness(FakeBackend(post=post))
                self.addCleanup(h.close)
                status, body, _ = h.classify({"texts": ["a", "b"]})
                self.assertEqual((status, body), (500, {"error": "backend_error"}))

    def test_score_noise_is_clamped(self):
        self.assertEqual(validate_scores([1.0000001, -1e-9], 2), [1.0, 0.0])

    def test_backend_exception_is_not_echoed(self):
        def explode(text):
            raise RuntimeError(f"failed on {text}")

        h = Harness(FakeBackend(scorer=explode))
        self.addCleanup(h.close)
        status, body, _ = h.classify({"texts": [SECRET_TEXT]})
        self.assertEqual((status, body), (500, {"error": "backend_error"}))
        self.assertNotIn("PRIVATE", h.log.getvalue())

    def test_logs_and_errors_never_contain_input_or_headers(self):
        self.h.classify({"texts": [SECRET_TEXT]}, {"Authorization": "Bearer hf_SECRETTOKEN"})
        self.h.classify({"texts": [SECRET_TEXT, "x" * 100]}, {"Authorization": "Bearer hf_SECRETTOKEN"})
        self.h.classify(b"{" + SECRET_TEXT.encode(), {"Authorization": "Bearer hf_SECRETTOKEN"})
        self.h.request("GET", "/" + SECRET_TEXT.replace(" ", "-"))
        logged = self.h.log.getvalue()
        self.assertIn('"status":200', logged)
        for forbidden in ("PRIVATE", "sk-live", "hf_SECRET", "Bearer"):
            self.assertNotIn(forbidden, logged)

    def test_concurrent_requests_stay_ordered(self):
        out = []

        def call(n):
            out.append((n, self.h.classify({"texts": [f"t{n}", TRIGGER]})))

        threads = [threading.Thread(target=call, args=(n,)) for n in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        for _, (status, body, _) in out:
            if status == 200:
                self.assertEqual(body, {"scores": [0.01, 0.99]})
            else:
                self.assertIn(body["error"], ("overloaded", "busy"))
        self.assertTrue(any(status == 200 for _, (status, _, _) in out))


class MicrobatchDeadlineTest(unittest.TestCase):
    """The deadline is cooperative: observed between micro-batches, not inside one."""

    def run_plan(self, count, batch, cost, deadline):
        now = [0.0]
        started = []

        def process(members):
            started.append(list(members))
            now[0] += cost

        try:
            run_in_microbatches(list(range(count)), batch, deadline, process, clock=lambda: now[0])
            outcome = "ok"
        except DeadlineExceeded:
            outcome = "deadline"
        return outcome, started, now[0]

    def test_completes_within_the_deadline(self):
        outcome, started, _ = self.run_plan(6, 2, 1.0, 10.0)
        self.assertEqual((outcome, started), ("ok", [[0, 1], [2, 3], [4, 5]]))

    def test_overrun_is_bounded_by_one_micro_batch(self):
        # 4 s per micro-batch, deadline 10 s: batches start at t=0, 4 and 8, the
        # last one finishes at 12 (2 s late), and no fourth batch starts.
        outcome, started, end = self.run_plan(8, 2, 4.0, 10.0)
        self.assertEqual((outcome, len(started), end), ("deadline", 3, 12.0))

    def test_smaller_micro_batches_shrink_the_overrun(self):
        # Same per-text cost (2 s), same deadline: the overrun is at most one micro-batch.
        for batch in (8, 4, 2, 1):
            with self.subTest(batch=batch):
                outcome, _, end = self.run_plan(32, batch, 2.0 * batch, 10.0)
                self.assertEqual(outcome, "deadline")
                self.assertLess(end - 10.0, 2.0 * batch)

    def test_last_micro_batch_cannot_return_a_late_success(self):
        outcome, started, _ = self.run_plan(2, 8, 11.0, 10.0)
        self.assertEqual((outcome, len(started)), ("deadline", 1))

    def test_expired_deadline_starts_nothing(self):
        outcome, started, _ = self.run_plan(4, 2, 1.0, 0.0)
        self.assertEqual((outcome, started), ("deadline", []))


class ConfigTest(unittest.TestCase):
    def test_defaults_pin_the_default_model(self):
        cfg = Config.from_env({})
        self.assertEqual(cfg.model_revision, DEFAULT_MODEL_REVISION)
        self.assertEqual(cfg.malicious_labels, ("INJECTION",))
        self.assertEqual(cfg.host, "127.0.0.1")

    def test_custom_model_requires_revision_and_labels(self):
        with self.assertRaises(ConfigError):
            Config.from_env({"SIDECAR_MODEL_ID": "org/model", "SIDECAR_MALICIOUS_LABELS": "BAD"})
        with self.assertRaises(ConfigError):
            Config.from_env({"SIDECAR_MODEL_ID": "org/model", "SIDECAR_MODEL_REVISION": "a" * 40})
        cfg = Config.from_env({"SIDECAR_MODEL_ID": "org/model", "SIDECAR_MODEL_REVISION": "a" * 40,
                               "SIDECAR_MALICIOUS_LABELS": "MALICIOUS, LABEL_1"})
        self.assertEqual(cfg.malicious_labels, ("MALICIOUS", "LABEL_1"))

    def test_revision_must_be_a_commit(self):
        for value in ("main", "A" * 40, "abc123"):
            with self.subTest(value), self.assertRaises(ConfigError):
                Config.from_env({"SIDECAR_MODEL_REVISION": value})

    def test_local_model_path_does_not_need_a_revision(self):
        cfg = Config.from_env({"SIDECAR_MODEL_ID": "org/model", "SIDECAR_MODEL_PATH": "/models/m",
                               "SIDECAR_MALICIOUS_LABELS": "MALICIOUS"})
        self.assertEqual(cfg.model_path, "/models/m")

    def test_invalid_numbers(self):
        for key, value in [("SIDECAR_PORT", "70000"), ("SIDECAR_MAX_TEXTS", "0"), ("SIDECAR_MAX_BODY_BYTES", "x"),
                           ("SIDECAR_INFERENCE_TIMEOUT_SECONDS", "nan"), ("SIDECAR_REQUEST_TIMEOUT_SECONDS", "0"),
                           ("SIDECAR_MALICIOUS_LABELS", "A,,B")]:
            with self.subTest(key), self.assertRaises(ConfigError):
                Config.from_env({key: value})


class LabelTest(unittest.TestCase):
    def test_resolution(self):
        self.assertEqual(resolve_label_indices({0: "SAFE", 1: "INJECTION"}, ["injection"]), [1])
        self.assertEqual(resolve_label_indices({0: "BENIGN", 1: "MALICIOUS", 2: "JAILBREAK"},
                                               ["MALICIOUS", "jailbreak"]), [1, 2])

    def test_wrong_mapping_fails_loudly(self):
        for labels in (["MALICIOUS"], ["SAFE", "INJECTION"], []):
            with self.subTest(labels), self.assertRaises(ValueError):
                resolve_label_indices({0: "SAFE", 1: "INJECTION"}, labels)


if __name__ == "__main__":
    unittest.main()
