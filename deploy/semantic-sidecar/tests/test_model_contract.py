"""Model contract: label verification and synchronization of the pinned defaults.

Offline and deterministic: nothing here loads a model or reads the network.
"""

import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))

from sidecar.backend import verify_label_mapping  # noqa: E402
from sidecar.config import DEFAULT_MODEL_ID, DEFAULT_MODEL_REVISION  # noqa: E402

PG2_86M = ("meta-llama/Llama-Prompt-Guard-2-86M", "a8ded8e697ce7c355e395a0df51f94adb4a2fd27",
           "e72017dbbe89c1232dcbc4a74ce0c389db5b468c42afd05850347b2a8c5f6b09")
PG2_22M = ("meta-llama/Llama-Prompt-Guard-2-22M", "11614a155199674a0a95e6602d6ab0417b790ed0",
           "5120e30bcd536ce285345d9ec104bea6bd6e8f94365b99a340c764f417ea5fa1")
DEBERTA = ("protectai/deberta-v3-base-prompt-injection-v2", "90c9989b1a342275dd0d1a95aad283c04e075671",
           "6521cb8d0ac08148c81464899c424e6148fcc62befa371089fa4061d8b6e0424")


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


class ContentTestCase(unittest.TestCase):
    """assertIn variants that do not dump whole files into the failure message."""

    def assertIn(self, needle, haystack, msg=None):  # noqa: N802
        if needle not in haystack:
            self.fail(f"{msg or 'missing'}: {needle!r} not found")

    def assertNotIn(self, needle, haystack, msg=None):  # noqa: N802
        if needle in haystack:
            self.fail(f"{msg or 'unexpected'}: {needle!r} found")


class LabelCheckTest(unittest.TestCase):
    """The malicious-label mapping is checked against the behavior of the loaded model."""

    @staticmethod
    def scorer(attack, benign):
        # Echoes the order of verify_label_mapping's two canary texts: attack first.
        return lambda texts: [attack, benign]

    def test_correct_mapping_passes(self):
        verify_label_mapping(self.scorer(0.9996, 0.0004))

    def test_inverted_mapping_is_refused(self):
        with self.assertRaises(ValueError):
            verify_label_mapping(self.scorer(0.0004, 0.9996))

    def test_constant_models_are_refused(self):
        for attack, benign in ((0.0, 0.0), (1.0, 1.0)):
            with self.subTest(attack=attack), self.assertRaises(ValueError):
                verify_label_mapping(self.scorer(attack, benign))

    def test_non_finite_or_out_of_range_scores_are_refused(self):
        nan, inf = float("nan"), float("inf")
        for attack, benign in ((nan, nan), (nan, 0.0), (1.0, nan), (inf, 0.0), (1.5, 0.0), (0.9, -0.5)):
            with self.subTest(attack=attack, benign=benign), self.assertRaises(ValueError):
                verify_label_mapping(self.scorer(attack, benign))

    def test_wrong_score_count_is_refused(self):
        with self.assertRaises(ValueError):
            verify_label_mapping(lambda texts: [0.9])

    def test_error_names_no_input(self):
        with self.assertRaises(ValueError) as caught:
            verify_label_mapping(self.scorer(0.1, 0.9))
        self.assertNotIn("instructions", str(caught.exception).lower())


class PinnedDefaultsTest(ContentTestCase):
    """Every place that repeats the default model must agree (Dockerfile, Compose, env, docs)."""

    def test_python_defaults(self):
        self.assertEqual((DEFAULT_MODEL_ID, DEFAULT_MODEL_REVISION), PG2_86M[:2])

    def test_dockerfile_defaults(self):
        text = read("Dockerfile")
        for name, value in (("MODEL_ID", PG2_86M[0]), ("MODEL_REVISION", PG2_86M[1]),
                            ("MODEL_SAFETENSORS_SHA256", PG2_86M[2])):
            declared = set(re.findall(rf"^ARG {name}=(\S*)$", text, re.M))
            self.assertEqual(declared, {value}, name)
        self.assertNotIn("protectai", text)

    def test_compose_defaults(self):
        text = read("compose.yaml")
        self.assertIn(f"${{SIDECAR_MODEL_ID:-{PG2_86M[0]}}}", text)
        self.assertIn(f"${{SIDECAR_MODEL_REVISION:-{PG2_86M[1]}}}", text)
        self.assertIn(f"${{SIDECAR_MODEL_SAFETENSORS_SHA256-{PG2_86M[2]}}}", text)
        self.assertIn("${SIDECAR_MALICIOUS_LABELS:-LABEL_1}", text)
        self.assertNotIn("protectai", text)

    def test_env_template(self):
        text = read("sidecar.env.template")
        self.assertIn(f"SIDECAR_MODEL_ID={PG2_86M[0]}", text)
        self.assertIn(f"SIDECAR_MODEL_REVISION={PG2_86M[1]}", text)
        self.assertIn("SIDECAR_MALICIOUS_LABELS=LABEL_1", text)
        self.assertIn("SIDECAR_VERIFY_LABELS=true", text)

    def test_profiles_pin_the_alternatives(self):
        for name, (model, revision, sha) in (("prompt-guard-2-22m", PG2_22M), ("deberta-fallback", DEBERTA)):
            text = read("profiles", f"{name}.env")
            self.assertIn(f"SIDECAR_MODEL_ID={model}", text)
            self.assertIn(f"SIDECAR_MODEL_REVISION={revision}", text)
            self.assertIn(f"SIDECAR_MODEL_SAFETENSORS_SHA256={sha}", text)
            self.assertTrue(re.search(r"(?m)^SIDECAR_MALICIOUS_LABELS=\S+$", text), name)

    def test_profile_labels(self):
        self.assertIn("SIDECAR_MALICIOUS_LABELS=LABEL_1", read("profiles", "prompt-guard-2-22m.env"))
        self.assertIn("SIDECAR_MALICIOUS_LABELS=INJECTION", read("profiles", "deberta-fallback.env"))

    def test_readme_documents_every_pin(self):
        text = read("README.md")
        for model, revision, sha in (PG2_86M, PG2_22M, DEBERTA):
            self.assertIn(model, text)
            self.assertIn(revision[:12], text)
            self.assertIn(sha[:12], text)

    def test_download_keeps_license_files(self):
        text = read("tools", "download_model.py")
        self.assertIn('"LICENSE*"', text)
        self.assertIn('"USE_POLICY*"', text)
        self.assertIn('".cache"', text)  # download bookkeeping is not shipped in the image

    def test_llama_attribution_ships_with_the_image(self):
        notice = read("notices", "llama4.txt")
        self.assertIn("Llama 4 is licensed under the Llama 4 Community License, "
                      "Copyright © Meta Platforms, Inc. All Rights Reserved.", notice)
        dockerfile = read("Dockerfile")
        self.assertIn("ARG MODEL_NOTICE=notices/llama4.txt", dockerfile)
        self.assertIn("Built with Llama", dockerfile)
        self.assertIn("Built with Llama", read("README.md"))


if __name__ == "__main__":
    unittest.main()
