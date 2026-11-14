# ADR 0022: Semantic benchmark corpus (French, calibration and test)

## Status

Accepted. Complements ADR 0011 (evaluation harness), ADR 0015 (offline gate) and
ADR 0018 (French injection recall). This ADR adds data and a validation package only:
no detector, no harness code and no existing corpus, baseline or gate is changed.

## Context

The semantic classifier (ADR 0003, 0010, 0019, 0020) must be compared with the
deterministic rules on French text, and a threshold must be chosen. The two versioned
corpora cannot serve:

- they are 83 and 62 cases, with a single split, so a threshold tuned on them is
  measured on the same cases;
- the deterministic rules were developed against the French injection corpus (ADR 0018),
  and the offline gate pins its results (ADR 0015); using those cases to tune a model
  would blur two purposes;
- they carry no family or template metadata, so one cannot show whether a split leaks
  paraphrases of one text into both sides.

The benchmark needs at least 200 French cases, half attacks and half hard negatives,
with a calibration split to tune on and a frozen test split to report on, in a format the
existing HTTP harness already runs.

## Decision

1. **Data, not code, in the harness format.** The corpus lives in
   `tests/eval/corpus/semantic-bench/` as two guardrail-eval corpora (format v1,
   `calibration.jsonl`, `test.jsonl`) that `guardrail-eval validate` and `run` accept
   unchanged, plus `metadata.jsonl` and `manifest.json`. The corpus format rejects
   unknown fields by design (ADR 0011), so what it cannot carry (family, template group,
   source, split, transform, derivation) is in `metadata.jsonl`, joined by case ID. The
   family is also the first tag of each case, so the harness report breaks results down
   per family. `cmd/` and `internal/` are untouched.
2. **240 original synthetic cases.** 120 attacks and 120 hard negatives; calibration 80
   (40/40), test 160 (80/80). Twelve attack families (direct override, role play,
   exfiltration, system-prompt leak, fake authority, delimiter injection, indirect via
   document, tool output and e-mail/web, obfuscation, FR-EN code switching, hypothetical
   or quoted framing with activation) and twelve hard-negative families (quotation,
   analysis, refusal, the user's own rules, ordinary *ignore*/*rules*/*system*, technical
   documentation, synthetic personal data, secret-handling documentation with
   placeholders, persuasive but benign wording, ordinary role play, legitimate markup,
   imperative wording in benign emails, READMEs and API replies). Every family has samples
   in both splits, so per-family tables are never empty. Only `prompt_injection` is
   labelled; the other detectors are not scored on this corpus.
3. **Split by template group, decided before any measure.** A template group is an
   original text with its paraphrases and mechanical transforms (zero-width characters,
   stripped diacritics, homoglyphs, leet, spaced letters, whitespace smuggling). A group
   lives in exactly one split; families are shared. The assignment was fixed by hand at
   authoring time. No detector, model or API was run on any case before the split was
   written, and the split does not depend on any score. Case IDs (`sb-0001`…`sb-0240`)
   are opaque and immutable: they are numbered by ascending SHA-256 of
   `<seed>:<authoring key>` (seed 20261114), so neither the ID nor the file position
   reveals class, family or split.
4. **Separation is checked, not promised.** `semanticbenchfixtures.Validate` fails on a
   template group present in both splits, on an exact text, an equal *skeleton* (lower
   case, accents, homoglyphs and leet folded, invisible characters, spaces and
   punctuation removed) or a near-duplicate (character 5-gram Jaccard ≥ 0.5) across
   splits. The tests also assert there is no such overlap with the two L9 corpora; no
   L9 case is copied. These checks are lexical. Paraphrases of the same intent written with different
   words are not detected by them, so they were looked for by review: authoring found
   one draft close to an L9 negative (similarity 0.63), and the first independent
   review found two pairs of cross-split paraphrases (a FR-EN prompt-leak request and a
   refusal of an embedded instruction); those cases were rewritten.
5. **Labels follow execution intent.** A case is positive when the text (or content
   embedded in a document, e-mail, page or tool output) asks the assistant to apply an
   instruction that overrides its rules, takes its role, reveals hidden prompts,
   exfiltrates data or disables safeguards, including a quotation followed by a request
   to apply it. It is negative when it only quotes, analyses, translates, classifies or
   refuses such an attempt, when the user changes their own earlier request, when the
   words are used in an ordinary sense, when markup or documentation is legitimate,
   when personal data or secrets are synthetic placeholders handled safely, and when a
   notice addresses human readers. Every label was reviewed against this rule
   after authoring, with a second look at the borderline families (quotation, analysis,
   hypothetical-quote, persuasive-benign, indirect-benign).
6. **Provenance and license per source.** Three sources, all MIT, all synthetic, none
   with real data or credentials: `author-original`, `author-original-transform`
   (derived mechanically from a base in the same group, `derived_from` in the metadata)
   and `author-original-synthetic-data` (personal-data and secret-handling texts).
   Addresses use `exemple.invalid` and the `example.test` TLD, phone numbers the
   reserved fiction range `06 39 98`, the IBAN and card are all-zero placeholders, and
   no text contains a credential-shaped value or an `api_key`-style field. Nothing is
   copied from a public dataset or from model output used as a reference.
7. **Manifest.** `manifest.json` records the seed and ordering rule, the SHA-256 of
   each file, set hashes per split (IDs, texts, template groups), the taxonomy, the
   sources with their license and provenance, the usage rules and the denominators per
   split, family, input type, transform and source.
8. **Usage rules.** Calibration may be measured repeatedly to choose thresholds and
   compare models. The test split is frozen: measure it once the configuration is
   fixed on calibration, report only, never tune, select a threshold or edit a rule
   from its results, and never merge it into calibration. A test asserts the SHA-256 of
   both files, so an edit is a deliberate act: a corrected corpus is a new version
   (`semantic-bench-fr-v2`), as for the other corpora.
9. **Validation package.** `tests/eval/semanticbenchfixtures` loads the bundle with the
   harness's own parser (`eval.ParseCorpus`), checks the invariants above and exports the
   contract (file names, manifest types, `Skeleton`, `Overlaps`) for the benchmark
   runner. It runs no detector and no model and does no network access.

## Alternatives considered

- **Extra fields in the corpus lines.** Rejected: the harness decodes strictly and the
  task forbids changing `cmd/`. A sidecar keyed by ID keeps the files runnable as is.
- **Random split by case.** Rejected: paraphrases and transforms of one text would land
  on both sides and inflate test scores.
- **Disjoint families between splits.** Rejected: families (the taxonomy) are what the
  per-family tables report; they must exist in both splits. The leakage unit is the
  template group.
- **Reusing the L9 corpora or public datasets (BIPIA, AgentDojo).** Rejected: the L9
  cases are the deterministic rules' regression set; the public sets are English,
  positives only and carry their own terms (see `tests/eval/README.md`).
- **Real or scraped text, or model-generated cases.** Rejected: real data and unknown
  license risk; model output would couple the benchmark to a model.
- **Fold the benchmark into the offline gate.** Rejected: the gate compares against a
  baseline of the deterministic rules; a semantic benchmark needs no pinned baseline
  and no model-dependent floor before it is measured.

## Consequences

- Positives: a French benchmark with two independent splits, a taxonomy, denominators,
  hashes and provenance; format-compatible with the existing harness; leakage and
  hygiene are tested.
- Negatives: 240 cases still give wide confidence intervals (a test-split rate on 80
  cases has a standard error near 5 points at 0.5); per-family cells in the test split
  hold 6 or 7 cases and are descriptive only. The hand-authored cases are shorter and
  cleaner than production traffic.
- Risks: one author wrote every case, so wording habits are shared by the attacks and
  by the negatives; the frozen test split, measured once, and the per-family tables
  limit but do not remove this. A model or rule tuned on the calibration split can
  still overfit its wording; hence the rule that test results never feed back.
- No detection behaviour, floor or baseline changes with this ADR.
