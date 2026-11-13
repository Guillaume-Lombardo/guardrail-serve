"""Fetch one pinned model snapshot at image build time (never at runtime).

Usage: download_model.py MODEL_ID REVISION DEST [EXPECTED_SAFETENSORS_SHA256]

The optional Hugging Face token is read from the file named by HF_TOKEN_FILE
(a BuildKit secret mount) and is never printed, logged or stored in the image.
Only safetensors weights, tokenizer/config files and the license texts (LICENSE,
USE_POLICY) are downloaded: no pickle formats, no ONNX, no code files.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys

ALLOW = ["*.json", "*.safetensors", "*.model", "LICENSE*", "USE_POLICY*", "NOTICE*", "README.md"]
IGNORE = ["onnx/*", "*/*", "*.onnx", "*.bin", "*.pt", "*.pth", "*.ckpt", "*.pkl", "*.py"]
HEX40 = set("0123456789abcdef")


def main(argv: list[str]) -> int:
    if len(argv) not in (4, 5):
        print(__doc__, file=sys.stderr)
        return 2
    model_id, revision, dest = argv[1:4]
    expected = argv[4].lower() if len(argv) == 5 and argv[4] else ""
    if len(revision) != 40 or not set(revision) <= HEX40:
        print("revision must be a full 40-character lowercase commit hash", file=sys.stderr)
        return 2

    token = None
    token_file = os.environ.get("HF_TOKEN_FILE", "")
    if token_file and os.path.isfile(token_file):
        with open(token_file, encoding="utf-8") as handle:
            token = handle.read().strip() or None

    from huggingface_hub import snapshot_download

    try:
        snapshot_download(
            repo_id=model_id, revision=revision, local_dir=dest, token=token,
            allow_patterns=ALLOW, ignore_patterns=IGNORE,
        )
    except Exception as exc:  # noqa: BLE001 - class name only: messages can include request details
        print(f"download failed: {type(exc).__name__} (gated model without a token, or unknown revision?)", file=sys.stderr)
        return 1

    # huggingface_hub keeps download bookkeeping (etags, lock files) here: not needed at runtime.
    shutil.rmtree(os.path.join(dest, ".cache"), ignore_errors=True)

    weights = os.path.join(dest, "model.safetensors")
    if not os.path.isfile(weights):
        print("model.safetensors is missing from the snapshot", file=sys.stderr)
        return 1
    digest = hashlib.sha256()
    with open(weights, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    print(f"model.safetensors sha256={digest.hexdigest()}")
    if expected and digest.hexdigest() != expected:
        print("model.safetensors sha256 does not match the expected value", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
