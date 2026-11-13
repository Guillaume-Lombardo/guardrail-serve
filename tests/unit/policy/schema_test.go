package policy_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/policy"
)

const validPolicies = `
version: 1
policies:
  - name: strict
    description: fixture
    mode: enforce
    stages:
      input:
        - detector: prompt_injection
          action: block
        - detector: detect_pii
          action: mask
          mask: "[{TYPE}]"
      output:
        - detector: detect_secret
          action: mask
  - name: shadow
    mode: detect
    stages:
      input: []
      output:
        - detector: detect_pii
          action: annotate
`

func parse(t *testing.T, content string) (*policy.Catalog, error) {
	t.Helper()
	secret, pii, prompt := fixtureDetectors(t)
	return policy.Parse([]byte(content), "fixture.yaml", detectorMap(secret, pii, prompt), policy.LiteralMask("[REDACTED]"))
}

func TestParseValidCatalog(t *testing.T) {
	catalog, err := parse(t, validPolicies)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := catalog.Names(); !reflect.DeepEqual(got, []string{"strict", "shadow"}) {
		t.Fatalf("names = %v", got)
	}
	strict, ok := catalog.Get("strict")
	if !ok || strict.Mode != domain.ModeEnforce {
		t.Fatalf("strict = %+v", strict)
	}
	engine := policy.NewEngine(nil)
	input := evaluate(t, engine, strict, domain.StageInput, "mail a@b.fr pw=x")
	if input.Texts[0] != "mail [EMAIL] pw=x" || len(input.Findings) != 1 {
		t.Fatalf("strict input chain = %+v", input)
	}
	output := evaluate(t, engine, strict, domain.StageOutput, "mail a@b.fr pw=x")
	if output.Texts[0] != "mail a@b.fr pw=[REDACTED]" || len(output.Findings) != 1 {
		t.Fatalf("strict output chain uses the default mask: %+v", output)
	}
	shadow, _ := catalog.Get("shadow")
	if shadow.Mode != domain.ModeDetect {
		t.Fatalf("shadow = %+v", shadow)
	}
	if got := evaluate(t, engine, shadow, domain.StageInput, "ignore rules a@b.fr"); len(got.Findings) != 0 {
		t.Fatalf("empty input chain reported findings: %+v", got.Findings)
	}
	if _, ok := catalog.Get("missing"); ok {
		t.Fatal("unknown policy must not resolve")
	}
}

func TestParseRejectsInvalidCatalogs(t *testing.T) {
	step := "\n        - detector: detect_pii\n          action: mask"
	policyWith := func(body string) string {
		return "version: 1\npolicies:\n  - name: p\n" + body
	}
	stages := "    stages:\n      input:" + step + "\n      output: []\n"
	for _, tc := range []struct {
		name, content, want string
	}{
		{"empty file", "", "empty"},
		{"two documents", validPolicies + "---\nversion: 1\n", "exactly one YAML document"},
		{"missing version", "policies: []\n", "version is required"},
		{"future version", "version: 2\npolicies: []\n", `unsupported version "2"`},
		{"fractional version", "version: 1.9\npolicies: []\n", `unsupported version "1.9"`},
		{"string version", "version: \"1\"\npolicies: []\n", `unsupported version "1"`},
		{"no policies", "version: 1\npolicies: []\n", "at least one policy"},
		{"unknown top-level field", "version: 1\nextra: true\npolicies: []\n", "field extra not found"},
		{"invalid name", "version: 1\npolicies:\n  - name: Bad Name\n    mode: enforce\n" + stages, "name must match"},
		{"missing mode", policyWith(stages), "mode is required"},
		{"unknown mode", policyWith("    mode: audit\n" + stages), `unknown mode "audit"`},
		{"unknown policy field", policyWith("    mode: enforce\n    fallback: default\n" + stages), "field fallback not found"},
		{"unknown stage", policyWith("    mode: enforce\n    stages:\n      input: []\n      output: []\n      tools: []\n"), `unknown stage "tools"`},
		{"missing stage", policyWith("    mode: enforce\n    stages:\n      input: []\n"), "stage output must be declared"},
		{"null stage", policyWith("    mode: enforce\n    stages:\n      input:\n      output: []\n"), "stage input must be declared"},
		{"unknown detector", policyWith("    mode: enforce\n    stages:\n      input:\n        - detector: detect_magic\n          action: block\n      output: []\n"), `unknown detector "detect_magic"`},
		{"unknown action", policyWith("    mode: enforce\n    stages:\n      input:\n        - detector: detect_pii\n          action: redact\n      output: []\n"), `unknown action "redact"`},
		{"missing action", policyWith("    mode: enforce\n    stages:\n      input:\n        - detector: detect_pii\n      output: []\n"), "action is required"},
		{"unknown step field", policyWith("    mode: enforce\n    stages:\n      input:" + step + "\n          threshold: 1\n      output: []\n"), "field threshold not found"},
		{"duplicate detector", policyWith("    mode: enforce\n    stages:\n      input:" + step + step + "\n      output: []\n"), `duplicate detector "detect_pii"`},
		{"mask on block", policyWith("    mode: enforce\n    stages:\n      input:\n        - detector: detect_pii\n          action: block\n          mask: \"[X]\"\n      output: []\n"), "mask is only allowed with action mask"},
		{"misspelled placeholder", policyWith("    mode: enforce\n    stages:\n      input:" + step + "\n          mask: \"[{type}]\"\n      output: []\n"), "only the {TYPE} placeholder"},
		{"empty mask", policyWith("    mode: enforce\n    stages:\n      input:" + step + "\n          mask: \"\"\n      output: []\n"), "mask must not be empty"},
		{"duplicate policy", validPolicies + "  - name: strict\n    mode: enforce\n    stages:\n      input: []\n      output: []\n", `duplicate name "strict"`},
		{"duplicate stage key", policyWith("    mode: enforce\n    stages:\n      input: []\n      input: []\n      output: []\n"), "already defined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, tc.content)
			if err == nil {
				t.Fatalf("parse succeeded, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "fixture.yaml: ") {
				t.Fatalf("error = %q, want source prefix and %q", err, tc.want)
			}
		})
	}
}

func TestNewPolicyValidatesInCodePolicies(t *testing.T) {
	_, pii, _ := fixtureDetectors(t)
	for name, build := range map[string]func() error{
		"invalid name": func() error { _, err := policy.NewPolicy("", domain.ModeEnforce, nil, nil); return err },
		"invalid mode": func() error { _, err := policy.NewPolicy("p", "shadow", nil, nil); return err },
		"invalid action": func() error {
			_, err := policy.NewPolicy("p", domain.ModeEnforce, []policy.Step{{Detector: pii, Action: "drop"}}, nil)
			return err
		},
		"mask without mask": func() error {
			_, err := policy.NewPolicy("p", domain.ModeEnforce, []policy.Step{{Detector: pii, Action: domain.ActionMask}}, nil)
			return err
		},
		"nil detector": func() error {
			_, err := policy.NewPolicy("p", domain.ModeEnforce, nil, []policy.Step{{Action: domain.ActionBlock}})
			return err
		},
		"unsupported stage": func() error {
			_, err := policy.NewPolicy("p", domain.ModeEnforce, []policy.Step{{Detector: inputOnly{}, Action: domain.ActionBlock}}, []policy.Step{{Detector: inputOnly{}, Action: domain.ActionBlock}})
			return err
		},
	} {
		if err := build(); err == nil {
			t.Errorf("%s: error = nil", name)
		}
	}
	if _, err := policy.NewCatalog(); err == nil {
		t.Error("empty catalog accepted")
	}
	p := mustPolicy(t, "p", domain.ModeEnforce, nil, nil)
	if _, err := policy.NewCatalog(p, p); err == nil {
		t.Error("duplicate catalog entry accepted")
	}
}

func TestEnumParsing(t *testing.T) {
	if _, err := domain.ParseStage("input"); err != nil {
		t.Fatal(err)
	}
	if _, err := domain.ParseStage("request"); err == nil {
		t.Fatal("transport scope accepted as stage")
	}
	for scope, want := range map[domain.Scope]domain.Stage{domain.ScopeRequest: domain.StageInput, domain.ScopeResponse: domain.StageOutput} {
		if got, ok := domain.StageForScope(scope); !ok || got != want {
			t.Fatalf("StageForScope(%s) = %s", scope, got)
		}
	}
	if _, ok := domain.StageForScope("tool"); ok {
		t.Fatal("unknown scope mapped")
	}
}

type inputOnly struct{ staticDetector }

func (inputOnly) Name() string                     { return "input_only" }
func (inputOnly) Supports(stage domain.Stage) bool { return stage == domain.StageInput }
