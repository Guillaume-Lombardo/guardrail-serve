# ADR 0020: Llama Prompt Guard 2 as the sidecar default

Built with Llama.

## Status

Accepted. Amends ADR 0019 (default model, label mapping, pinned revision).

## Context

ADR 0019 shipped a real semantic sidecar whose default model was
`protectai/deberta-v3-base-prompt-injection-v2` because Llama Prompt Guard 2 is
gated and could not be downloaded at that time. The L10 evaluation showed that this
English model produces many false positives on French text (87% of the French
injection negatives, 52% of the original negatives). Meta publishes a multilingual
86M model and an English-first 22M model for the same job. This change makes the 86M
model the default, keeps the 22M model as a configuration option and keeps DeBERTa as
an explicit fallback.

## Verified facts

Read from the checkpoints at the pinned revisions with the operator's own access,
never from memory:

| Checkpoint | Revision | `model.safetensors` sha256 | Architecture | Size |
| --- | --- | --- | --- | --- |
| `meta-llama/Llama-Prompt-Guard-2-86M` | `a8ded8e697ce7c355e395a0df51f94adb4a2fd27` | `e72017dbbe89…5f6b09` | `DebertaV2ForSequenceClassification` (mDeBERTa-v3-base), 2 labels, 512 tokens | 1.1 GB |
| `meta-llama/Llama-Prompt-Guard-2-22M` | `11614a155199674a0a95e6602d6ab0417b790ed0` | `5120e30bcd53…5fa1` | `DebertaV2ForSequenceClassification` (DeBERTa-v3-xsmall), 2 labels, 512 tokens | 283 MB |
| `protectai/deberta-v3-base-prompt-injection-v2` (fallback) | `90c9989b1a342275dd0d1a95aad283c04e075671` | `6521cb8d0ac0…0424` | `DebertaV2ForSequenceClassification`, labels `SAFE` / `INJECTION` | n/a |

- The tokenizer loads with the standard `AutoTokenizer`; no custom code is needed and
  `trust_remote_code` is never enabled.
- **The Prompt Guard 2 checkpoints declare no `id2label`.** `transformers` therefore
  names the classes `LABEL_0` and `LABEL_1`. The model card speaks of "benign" and
  "malicious" prompts, but the label `MALICIOUS` mentioned in ADR 0019 and in earlier
  docs does not exist in the checkpoint. That `LABEL_1` is the malicious class was
  confirmed with the real model: a clear attack scores 0.998 or more and a benign
  sentence about 0.0004 on that class. A configuration naming `MALICIOUS` makes the sidecar
  refuse to load ("none of the malicious labels exists in the model"), which was
  checked with the real model. The malicious label is `LABEL_1`.
- Both models are public to anyone who has accepted the license on their Hugging
  Face account; the download needs that account's token.

## Decision

1. **Default model**: `meta-llama/Llama-Prompt-Guard-2-86M`, with a pinned revision
   and a verified sha256 for the weights. The 22M model and DeBERTa are shipped as
   ready-made profiles (`deploy/semantic-sidecar/profiles/*.env`) with their own
   pinned revision, hash and label. A non-default model still requires an explicit
   revision and labels: no implicit "latest".
2. **Explicit label mapping.** The malicious labels are configured
   (`SIDECAR_MALICIOUS_LABELS`, default `LABEL_1`); the score of a text is the sum of
   the softmax probabilities of the declared malicious labels. A name that does not
   exist in the model is a load error, never an empty sum.
3. **Load-time canary** (`SIDECAR_VERIFY_LABELS`, default on). After warm-up, the
   sidecar scores one clear attack and one benign sentence and refuses to start when
   the attack is below 0.5 or the benign sentence is at 0.5 or more. This catches an
   inverted, constant or mistyped mapping before it serves traffic. The check
   was exercised with the real model: mapping the malicious class to `LABEL_0` makes
   startup fail. The error never contains the canary text of a request.
4. **No remote code, offline runtime.** Unchanged from ADR 0019: the image has no
   token, no network at runtime (`internal: true` network, `HF_HUB_OFFLINE`), and the
   container hardening and graceful drain of L10 still apply.
5. **Build authentication through a BuildKit secret only.** The token is passed as
   `--secret id=hf_token` (Compose: `secrets.hf_token.environment: HF_TOKEN`) and read
   by `RUN --mount=type=secret` in the download stage. It is never an `ARG`, an `ENV`,
   a repository file or an image layer, and the download tool removes the Hugging
   Face cache directory. An unset `HF_TOKEN` gives an empty secret, so the public
   DeBERTa fallback still builds without a token. The former `compose.gated.yaml`
   override is removed: the same `compose.yaml` serves every model.
6. **Licensing obligations are built in** (see "License" below): the agreement and the
   acceptable-use policy are kept in the image, a `NOTICE` file carries the required
   attribution, and "Built with Llama" appears in the documentation and in an image
   label. This project publishes no image and no weights.
7. **Go side unchanged.** No CGO, no model code in the Go binary, no new dependency;
   the `scores` contract is the same. Only the example documentation and the TEI
   label note change.

## License

The Prompt Guard 2 repositories carry the **Llama 4 Community License Agreement**
(effective April 5, 2025, `license: other`, `license_name: llama4` in the metadata)
and the Llama 4 Acceptable Use Policy (`USE_POLICY.md`). The same `LICENSE` file
(sha256 `73755cee…2917`) is in the 86M and 22M repositories. This is an engineering
summary, not legal advice; the text prevails.

| Obligation | Where it is met |
| --- | --- |
| Provide a copy of the agreement to recipients of the Llama Materials | The download keeps `LICENSE` and `USE_POLICY.md`; the image has them in `/models/model/`. |
| Keep the attribution notice ("Llama 4 is licensed under the Llama 4 Community License, Copyright © Meta Platforms, Inc. All Rights Reserved.") in a "Notice" text file | Image `/models/NOTICE` (from `notices/llama4.txt`) and the repository `NOTICE`. |
| Display "Built with Llama" on a related website, user interface, blog post, about page or product documentation | The sidecar README, the root README and this ADR; image label `io.guardrail-serve.model.attribution`. An operator who builds a product on the image owns the display in their own interface or docs. |
| Comply with the Acceptable Use Policy and applicable law | Operator responsibility; stated in the README. |
| Prefix the name of an AI model trained or improved with Llama materials with "Llama" | Not applicable: no training or fine-tuning here. |
| Separate license from Meta above 700 million monthly active users | Operator responsibility. |

The MIT license of this repository does **not** cover the weights. The repository
holds no weights, no Meta code and no image. Whoever builds an image from
`deploy/semantic-sidecar` and shares or pushes it becomes a distributor and owns these
obligations; that is why the documentation says so next to the build command. The
DeBERTa fallback is Apache-2.0 and is not Llama Materials: its image uses its own
notice (`notices/protectai-deberta.txt`) and carries no Llama attribution.

## Consequences

- The default image is bigger: 1.1 GB of weights and about 290 MiB more memory than the
  DeBERTa image in the evaluation; the 2 GiB Compose limit still holds (peak 1247 MiB
  with the real model in the Compose run).
- Building the default image needs a Hugging Face account with access to the gated
  repositories. The fallback and a cached build do not.
- A future model or revision change is an explicit edit of the revision, the hash and
  the labels in one place per file; `tests/test_model_contract.py` fails when the
  Python defaults, the Dockerfile, Compose, the environment template, the profiles and
  the documentation disagree.
- The docs' former `MALICIOUS` label is corrected everywhere; operators using
  Text Embeddings Inference with these checkpoints must use `LABEL_1`.

## Evaluation and mode rule

Measured on `codex-dev` with the real service, a threshold of `0.9` fixed beforehand,
the French injection corpus (62 cases) and the original corpus (83 cases) kept
separate; full tables in [EVALUATION.md](../../deploy/semantic-sidecar/EVALUATION.md).

| Set | Mode | 86M TP/FP/TN/FN | DeBERTa TP/FP/TN/FN |
| --- | --- | --- | --- |
| French injection (31 + 31) | semantic | 11/4/27/20 | 30/27/4/1 |
| French injection | deterministic + semantic | 30/5/26/1 | 31/27/4/0 |
| Original, global (13 + 70) | semantic | 8/0/70/5 | 13/36/34/0 |
| Original, global | deterministic + semantic | 13/1/69/0 | 13/37/33/0 |

DeBERTa reproduces the L10 counts exactly, so the protocols are comparable.

Predefined rule: the semantic detector may move from `annotate` to `block` in the
examples only if the French false-positive rate is at most 5% and recall does not
fall below 29/31 on the French injection corpus and 6/6 on the original French cases.
Recall holds (30/31 and 6/6), but the combined French FPR is 16.1% (5/31), so the
example policies **stay in `annotate`**. The default model change stands independently
of this rule: it removes 23 false positives on the French injection corpus and 36 on the original corpus when the semantic detector runs alone.

## Alternatives considered

- **Keep DeBERTa as the default**: better recall alone, but 87% FPR on French
  negatives; rejected as a default, kept as a fallback profile.
- **Default to the 22M model**: half the latency and memory, but 5/31 French attacks
  found alone and an English-first pretraining; kept as an option.
- **Lower the threshold to recover recall**: not done. The threshold was fixed before
  the measurement and is not selected on the test sets; the threshold-free diagnostic
  in EVALUATION.md shows no threshold that fixes the French recall at a low FPR.
- **Remove the canary and trust the model card**: the card's label does not exist in the
  checkpoint; a canary is the cheapest guard against a silent inversion.
- **Publish an image**: rejected; it would make this project a distributor of Llama
  Materials.

## Limits

Small samples, public synthetic corpora, one threshold, one shared VM, no
confidence intervals. The 86M model alone finds about a third of the French
injection attacks at `0.9`; its value here is the near absence of false positives.
