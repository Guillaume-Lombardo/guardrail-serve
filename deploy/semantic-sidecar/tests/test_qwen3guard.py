"""Bench Qwen3Guard backend: strict parsing and the injection decision, offline (no model)."""

import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "bench"))

from sidecar.backend import CANARY_ATTACK, TextTooLong  # noqa: E402
from qwen3guard import InvalidAssessment, Qwen3GuardBackend, injection_score, parse_assessment  # noqa: E402


class FakeTokenizer:
    """Chat template stand-in: one token per character of a fixed wrapper plus the text."""

    def apply_chat_template(self, messages, tokenize):
        assert tokenize is False and len(messages) == 1 and messages[0]["role"] == "user"
        return "<user>" + messages[0]["content"] + "</user>"

    def __call__(self, prompt, add_special_tokens):
        assert add_special_tokens is False
        return {"input_ids": [ord(c) for c in prompt]}


def fake_generate(outputs):
    """Answer by text content: the decoded prompt picks the canned assessment."""

    def generate(ids):
        prompt = "".join(chr(i) for i in ids)
        for needle, answer in outputs.items():
            if needle in prompt:
                return answer
        return "Safety: Safe\nCategories: None"

    return generate


class ParseTest(unittest.TestCase):
    def test_valid_assessments(self):
        self.assertEqual(parse_assessment("Safety: Safe\nCategories: None"), ("Safe", ()))
        self.assertEqual(parse_assessment("Safety: Unsafe\nCategories: Jailbreak\n"), ("Unsafe", ("Jailbreak",)))
        self.assertEqual(parse_assessment("Safety: Controversial\nCategories: None"), ("Controversial", ()))
        self.assertEqual(parse_assessment("Safety: Unsafe\nCategories: PII, Jailbreak"), ("Unsafe", ("PII", "Jailbreak")))

    def test_rejects_malformed_output(self):
        for content in (
            "",
            "Safety: Unsafe",
            "Safety: unsafe\nCategories: Jailbreak",
            "Safety: Unsafe\nCategories: Prompt Injection",
            "Safety: Unsafe\nCategories: Jailbreak, Jailbreak",
            "Safety: Unsafe\nCategories: None",
            "Safety: Safe\nCategories: Jailbreak",
            "Safety: Unsafe\nCategories: Jailbreak\nRefusal: No",
            "Sure! Safety: Unsafe\nCategories: Jailbreak",
        ):
            with self.subTest(content=content), self.assertRaises(InvalidAssessment):
                parse_assessment(content)

    def test_only_jailbreak_is_an_injection(self):
        self.assertEqual(injection_score("Safety: Unsafe\nCategories: Jailbreak")[0], 1.0)
        self.assertEqual(injection_score("Safety: Controversial\nCategories: Jailbreak")[0], 1.0)
        self.assertEqual(injection_score("Safety: Unsafe\nCategories: PII")[0], 0.0)
        self.assertEqual(injection_score("Safety: Unsafe\nCategories: Violent, Unethical Acts")[0], 0.0)
        self.assertEqual(injection_score("Safety: Safe\nCategories: None")[0], 0.0)


class BackendTest(unittest.TestCase):
    def make(self, outputs, verify=True):
        return Qwen3GuardBackend(model_path="", max_tokens=200, threads=0, verify_labels=verify,
                                 generate=fake_generate(outputs), tokenizer=FakeTokenizer())

    def test_scores_are_binary_and_in_order(self):
        backend = self.make({CANARY_ATTACK: "Safety: Unsafe\nCategories: Jailbreak",
                             "attack": "Safety: Unsafe\nCategories: Jailbreak",
                             "email": "Safety: Unsafe\nCategories: PII"})
        scores = backend.score(["benign", "attack", "email"], max_tokens=200, deadline=time.monotonic() + 60)
        self.assertEqual(scores, [0.0, 1.0, 0.0])

    def test_canary_refuses_a_model_that_never_flags(self):
        with self.assertRaises(ValueError):
            self.make({})

    def test_invalid_output_is_an_error_not_a_score(self):
        backend = self.make({CANARY_ATTACK: "Safety: Unsafe\nCategories: Jailbreak", "odd": "I cannot help."})
        with self.assertRaises(InvalidAssessment):
            backend.score(["odd"], max_tokens=200, deadline=time.monotonic() + 60)

    def test_token_limit_counts_the_whole_prompt(self):
        backend = self.make({CANARY_ATTACK: "Safety: Unsafe\nCategories: Jailbreak"})
        with self.assertRaises(TextTooLong) as raised:
            backend.score(["short", "x" * 300], max_tokens=200, deadline=time.monotonic() + 60)
        self.assertEqual(raised.exception.index, 1)


if __name__ == "__main__":
    unittest.main()
