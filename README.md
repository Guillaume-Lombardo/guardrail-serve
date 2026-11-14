# guardrail-serve

A small Go service that checks LLM traffic before and after the model: it masks
secrets and personal data, and blocks prompt injections. It plugs into
[LiteLLM](https://docs.litellm.ai/docs/adding_provider/generic_guardrail_api)
as a generic guardrail, or can be called directly over HTTP.

- **Deterministic first**: regex and validator rules embedded in a static binary,
  sub-millisecond per request, no model or network needed.
- **Explainable decisions**: `NONE`, `GUARDRAIL_INTERVENED` (texts masked) or
  `BLOCKED`, with findings that point at the original text and never contain the
  matched value.
- **Configurable policies**: chains of detectors per stage (request / response),
  in `enforce` or `detect` (audit) mode, loaded from YAML.
- **Optional semantic layer**: a prompt-injection classifier
  (Llama Prompt Guard 2) served by a separate CPU sidecar, and an external judge
  (TypeSafe System One) for uncertain scores, called only on masked text. Both are
  disabled by default.

## What it detects

| Detector | Covers |
| --- | --- |
| `detect_secret` | 217 pinned gitleaks rules, keyword assignments, entropy |
| `detect_pii` | email, phone, IBAN (MOD 97), payment card (Luhn), IP, French NIR/SIREN/SIRET |
| `prompt_injection` | English and French instruction overrides, system-prompt disclosure, hostile tool use |
| `max_length` | number of texts and total length |
| `semantic_prompt_injection` | optional model-based injection score |

All detectors run on a normalized view of the text (NFKC, invisible characters
removed), so full-width, ligature and zero-width tricks do not bypass them.

## Install

Requirements: Go 1.26 (see `go.mod`). Docker is optional.

**From source**

```sh
git clone https://github.com/Guillaume-Lombardo/guardrail-serve.git
cd guardrail-serve
cp .env.template .env            # adjust if needed; every setting has a default
set -a; . ./.env; set +a         # the binary reads the environment, not .env
go run ./cmd/guardrail-serve
curl http://127.0.0.1:8000/health/
```

**With Docker**

```sh
docker build -t guardrail-serve .
docker run --rm -p 127.0.0.1:8000:8000 -e GUARDRAIL_API_KEYS=change-me guardrail-serve
```

The image is static, distroless and non-root. Set `GUARDRAIL_API_KEYS` as soon as
the service is reachable by others.

**Try it**

```sh
curl -s http://127.0.0.1:8000/v1/guardrails/default \
  -H 'Content-Type: application/json' \
  -d '{"texts":["write to zoe@ex.fr"]}'
# -> "decision": "GUARDRAIL_INTERVENED", "texts": ["write to [EMAIL]"]
```

Swagger UI is on `/docs`, the OpenAPI document on `/openapi.json` and `/openapi.yaml`.

**Use it from LiteLLM**

```yaml
guardrails:
  - guardrail_name: guardrail-serve
    litellm_params:
      guardrail: generic_guardrail_api
      mode: [pre_call, post_call]
      api_base: http://guardrail-serve:8000
      additional_provider_specific_params:
        policy: default
```

**Optional semantic sidecar**: see [`deploy/semantic-sidecar`](deploy/semantic-sidecar/README.md).
It needs your own Hugging Face access to the gated Prompt Guard 2 model, or uses a
public fallback model.

## Results

Measured with the offline evaluation gate (fixed corpora, real HTTP service) and,
for the model, on the build host with 2 shared vCPUs. Details and protocol:
[evaluation](docs/evaluation.md) and [sidecar evaluation](deploy/semantic-sidecar/EVALUATION.md).

| Scope | Recall | False positives |
| --- | ---: | ---: |
| PII, original corpus (83 cases, FR + EN) | 100% | 6% |
| Secrets, original corpus | 88 to 89% | 0 to 3% |
| Prompt injection, original corpus | 100% | 0 to 3% |
| Prompt injection, French corpus (62 cases), rules only | 93.5% | 3.2% |
| Same, rules + Prompt Guard 2 86M | 96.8% | 16.1% |

| Latency per request | p50 |
| --- | ---: |
| Deterministic detectors | ~0.3 ms |
| Prompt Guard 2 86M sidecar (CPU) | +165 to 170 ms |

The model adds little recall on French text for many more false positives, so the
example policies keep it in `annotate` (report only) while the rules block.

## Documentation

| Topic | Where |
| --- | --- |
| Routes, policies, LiteLLM contract | [docs/api.md](docs/api.md) |
| Configuration, container, logging, metrics | [docs/operations.md](docs/operations.md) |
| How each detector works, semantic detector | [docs/detectors.md](docs/detectors.md) |
| Evaluation gate and corpora | [docs/evaluation.md](docs/evaluation.md) |
| Architecture decisions | [docs/adr](docs/adr/README.md) |
| Contributing, agent workflow | [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md), [.agents/](.agents/) |

## Development

```sh
gofmt -w .
go test ./...
go test ./tests/integration/... ./tests/end2end/...
scripts/eval-offline.sh
pre-commit run --all-files
```

Layout: `cmd/` (service and evaluation CLI), `internal/` (domain, detectors,
policy engine, HTTP API), `tests/` (unit, integration, end2end, eval),
`deploy/` (semantic sidecar), `docs/`.

## License

MIT, see [LICENSE](LICENSE) and [NOTICE](NOTICE) for embedded third-party rules.
The optional sidecar can download Llama Prompt Guard 2, licensed separately under
the Llama 4 Community License (Built with Llama).
