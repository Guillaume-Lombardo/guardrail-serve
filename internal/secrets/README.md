# internal/secrets

Native, deterministic secret detection for free text. The package depends only
on the Go standard library and knows nothing about policies, HTTP, the
guardrail engine or environment variables: callers build a `Config`
explicitly and adapt `Finding` values to their own contracts.

Design rationale: [ADR 0009](../../docs/adr/0009-native-secret-detection.md).
Third-party attribution: [NOTICE](../../NOTICE).

## API

```go
scanner, err := secrets.New(secrets.DefaultConfig())
findings, err := scanner.Scan(ctx, text)
```

- `New(Config) (*Scanner, error)` validates the configuration. A `Scanner`
  is immutable and safe for concurrent use.
- `Scan(ctx, text)` returns findings sorted by start, end, source and rule.
  Its only error is the context error (`ctx.Err()`), checked between rules
  and sources.
- `Rules()` lists the rule names a scanner can report, sorted.
- `ExcludedGitleaksRules()` lists the vendored gitleaks rules that never
  apply to free text, with the reason.

A `Finding` has:

| Field | Meaning |
|---|---|
| `Source` | `gitleaks`, `keyword` or `entropy` |
| `Rule` | `gitleaks:<rule-id>`, `keyword:<group>`, `entropy:base64`, `entropy:hex` |
| `Type` | `SECRET` (gitleaks, keyword) or `HIGH_ENTROPY_STRING` (entropy) |
| `Start`, `End` | Unicode code point (rune) offsets in the original text, end exclusive |
| `ByteStart`, `ByteEnd` | the same span in bytes, on rune boundaries |
| `Score` | Shannon entropy of the span for entropy findings, `nil` otherwise |

Findings never carry the matched value, and no error contains scanned text.
Invalid UTF-8 bytes count as one rune each, as `utf8.RuneCountInString` does.

## Configuration

| Field | Default | Validation |
|---|---|---|
| `Gitleaks.Enabled` | `true` | at least one source must be enabled |
| `Gitleaks.DisabledRules` | none | gitleaks ids without prefix; unknown or excluded ids are errors; requires gitleaks enabled |
| `Keywords.Enabled` | `true` | |
| `Entropy.Enabled` | `true` | |
| `Entropy.Base64Threshold` | `4.5` | in `(0, 8]` |
| `Entropy.HexThreshold` | `3.0` | in `(0, 8]` |
| `Entropy.MinBase64Length` | `20` | `>= 1`, in characters |
| `Entropy.MinHexLength` | `16` | `>= 1`, in characters |

Settings of a disabled source are not validated.

## Sources and precedence

Every source runs on the original text. Overlaps are then resolved by source
rank, `gitleaks` > `keyword` > `entropy`: a finding whose span is contained in
a finding of a stronger source is dropped, and duplicates of the same source
and span are merged. Two different gitleaks rules on the same span are both
kept (they are distinct facts). Partial overlaps are kept.

### gitleaks

`rules/gitleaks.toml` is the gitleaks default configuration, version v8.30.1,
commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`, vendored byte for byte
below a provenance and MIT license header (a test checks the upstream
SHA-256). It is parsed by a strict TOML subset parser at first use: any
unknown key, table or syntax is an error, so an upstream refresh cannot
silently drop a field. Every regular expression compiles with Go RE2.

Semantics reproduced from gitleaks `detect/detect.go`:

- keyword prefilter: a rule with keywords runs only when the lowercased text
  contains one of them;
- every match, with leading and trailing `\n` trimmed;
- the secret is `secretGroup` when set, otherwise the first non-empty
  capture group, otherwise the whole match;
- `entropy`: the secret is skipped when its Shannon entropy is `<=` the rule
  threshold;
- global allowlist, then rule allowlists: `condition` OR/AND, `regexTarget`
  `secret` (default), `match` or `line`, case-insensitive `stopwords` on the
  secret;
- generic-rule precedence: a `generic-api-key` finding is dropped when a
  non-generic finding on the same line contains its secret.

The reported span is the secret, not the whole match.

Deliberate differences:

- The inline `gitleaks:allow` comment is ignored: in a guardrail, the scanned
  text is untrusted and such a marker would be a trivial bypass.
- Allowlist `paths` and `commits` never match (there is no file or commit).
  A rule whose only matcher is a path, or whose path regex cannot match the
  empty path, is excluded; `ExcludedGitleaksRules` lists them
  (`freemius-secret-key`, `hashicorp-tf-password`, `kubernetes-secret-yaml`,
  `nuget-config-password`, `pkcs12-file` in v8.30.1). The active set has 217
  rules.
- `regexTarget = "line"` uses the lines spanned by the trimmed match.
- Entropy counts Unicode code points (gitleaks iterates runes too; the result
  only differs for invalid UTF-8).
- Decoding passes (base64/hex/percent decoding before rescanning) are not
  implemented. Unsupported rule or config fields (`required`, `skipReport`,
  `extend`, `allowlist.targetRules`...) are load errors, so a future refresh
  using them fails loudly instead of changing semantics silently.

### keyword

After the detect-secrets `KeywordDetector` (itself derived from Bandit),
rewritten for RE2 and free text. One pattern finds `key <op> value` shapes on
a line:

- key: up to 64 letters, digits, `_`, `.`, `-`, or `mot de passe`; it may be
  followed by up to two closing quotes or `]` (`"password":`, `['password']`);
- operator: `:=`, `=>`, `=`, `==`, `===`, `!=`, `!==`, `:`, `>` (XML), the
  full-width `：` and `＝`, or the prose connectors `is`, `est`, `was`;
  horizontal white space includes tabs, no-break and narrow no-break spaces;
- value: a quoted string (`"`, `'`, `` ` ``) or an unquoted run up to white
  space or a delimiter.

The key is split into words (separators, then camelCase) and classified into a
group: `password` (password, passwd, pwd, passphrase, `pass` after a
qualifier as in `db_pass`, mdp, mot de passe, contraseña…), `secret`,
`api_key`, `token`, `credential`, `authorization`.
Keywords match the end of a separator word (`dbpass`, `appsecret`), with
qualifiers before them. Keys that describe a secret instead of holding it are
not secret keys: a descriptor after the keyword (`password_length`,
`token_url`, `secret_name`, `passwordHint`), a negating prefix (`public_key`,
`csrf_token`, `nextPageToken`, `max_tokens`) or an identifier suffix
(`api_key_id`, `client_id`). `Authorization` values skip the scheme (`Basic`,
`Token`, `Bearer`…). A standalone `Bearer <credential>` of at least 16
characters is also reported as `keyword:bearer`.

Value rules (deterministic, in this order):

1. minimum length: 4 characters quoted, 6 unquoted;
2. placeholders are rejected: schema words and stopwords (`required`,
   `null`, `redacted`, `password`…), a single repeated character
   (`********`), templates (`{x}`, `<x>`, `[x]`, `${x}`, `{{ x }}`, `%x%`,
   `%(x)s`), `$VAR`, and letter-only values containing `your`, `here`,
   `example`, `placeholder`…;
3. at least one letter or digit; digit-only values only for passwords (PINs),
   not for `token: 4096`;
4. quoted values are accepted at this point;
5. unquoted values are rejected when they are comparisons (`!=`, `==`), calls
   or subscripts (`get_secret()`, `env['KEY']`), `UPPER_SNAKE` names, dotted
   attribute paths (`config.secret`), paths or URLs; otherwise they need a
   digit, a symbol or an inner capital letter (plain words are prose).

A final sentence dot is trimmed from unquoted values.

### entropy

After detect-secrets `Base64HighEntropyString`, `HexHighEntropyString` and
`filters/heuristic.py`. Candidates are maximal runs of the base64 alphabet
(`A-Z a-z 0-9 + / - _ =`), split at internal `=` padding and, inside URLs
only, at `/` (each path segment is a candidate). A candidate of only hex
digits uses the hex threshold and `MinHexLength`, with the detect-secrets
all-digit adjustment (`- 1.2 / log2(len)`); other candidates use the base64
threshold and `MinBase64Length`. A candidate is reported when its entropy is
strictly greater than the threshold.

Always filtered: candidates without an ASCII letter, sequential strings (the
detect-secrets alphabets), templated candidates (`{x}`, `<x>`) and
`$`-prefixed references.

Filtered unless the candidate is the value of a secret keyword assignment
(strong context, e.g. `api_key = <40 hex>`):

- an exact UUID;
- the value of an identifier key (`user_id`, `tenantId`);
- a `;base64,` data URI payload and subresource integrity digests
  (`sha384-…`);
- a likely digest: a bare single-case 40 or 64 hex string (git SHA-1/SHA-256
  object ids), or a hex candidate preceded within 32 bytes on the same line by
  a hash word (`commit`, `sha256`, `digest`, `checksum`, `etag`…).

Strong context therefore beats the hash shape: a real key that looks like a
git SHA is still reported when it is assigned to a secret key.

## Known limits

- Unquoted plain-word passwords (`password: sunshine`) and `--password value`
  without an operator are not reported (prose false positives would
  dominate).
- Zero-width characters and homoglyphs inside keys are left to text
  normalization upstream of this package.
- A secret inside a long base64 run is diluted by the surrounding characters
  (one run, one entropy).
- No decoding passes: a base64-encoded provider token is reported only by
  entropy.
- Findings are per text; there is no line/column, file or commit metadata.

## Tests and corpus

`corpus_test.go` holds synthetic provider tokens generated at test time from
a fixed-seed PRNG (no real secrets in the repository), contextual secrets,
benign text (git SHAs, UUIDs, URL path segments, templates, sequences, code),
random base64/hex fixtures and threshold edges. The corpus is representative,
not exhaustive: it pins the behaviour of the heuristics above and guards
against false-positive avalanches and trivial context bypasses, but it does
not prove recall on real-world data.
