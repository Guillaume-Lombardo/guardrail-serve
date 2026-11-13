package api_test

import (
	"encoding/json"
	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeSecretsJourneys(t *testing.T) {
	handler := newTestHandler(t)
	cases := []struct{ name, text, want string }{
		{"git", "commit 4101aa9cf6c2f28eb8a6815dbcc8a225e314086d", "commit 4101aa9cf6c2f28eb8a6815dbcc8a225e314086d"},
		{"uuid", "user_id=550e8400-e29b-41d4-a716-446655440000", "user_id=550e8400-e29b-41d4-a716-446655440000"},
		{"url", "https://example.org/documentation/configuration/reference", "https://example.org/documentation/configuration/reference"},
		{"strong hash", "password=4101aa9cf6c2f28eb8a6815dbcc8a225e314086d", "password=[REDACTED]"},
		{"french", "Été 🙂 mot de pa\u200bsse＝Tr0u\u200bb4dor&3x", "Été 🙂 mot de pa\u200bsse＝[REDACTED]"},
		{"provider", "ghp_Ab3dEf7hIj9lMn2pQr4tUv6xYz8BcDeFgHiJ", "[REDACTED]"},
		{"entropy", "q7V9m2Z4r8B1n6C3x5K0pA+e/DfGhJkL", "[REDACTED]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, path := range []string{"/scan/secrets", "/v1/guardrails/detect_secret", "/beta/litellm_basic_guardrail_api"} {
				for _, stage := range []string{"request", "response"} {
					body, _ := json.Marshal(map[string]any{"texts": []string{c.text}, "input_type": stage})
					r := post(t, handler, path, string(body))
					if r.Code != 200 {
						t.Fatalf("%s: %d", path, r.Code)
					}
					var out struct {
						Texts []string `json:"texts"`
					}
					if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
						t.Fatal(err)
					}
					if len(out.Texts) != 1 || out.Texts[0] != c.want {
						t.Errorf("%s %s: unexpected masked text", path, stage)
					}
					if c.text != c.want && strings.Contains(r.Body.String(), c.text) {
						t.Errorf("%s: raw secret leaked", path)
					}
				}
			}
		})
	}
}

func TestNativeSecretOriginalFindingsAndTypedMasks(t *testing.T) {
	// default policy uses its literal mask; the audit policy leaves text intact
	// while exposing original rune spans and native types.
	text := "Été 🙂 mot de pa\u200bsse＝Tr0u\u200bb4dor&3x"
	body, _ := json.Marshal(map[string]any{"texts": []string{text}})
	got := decodePolicy(t, post(t, newTestHandler(t), "/v1/guardrails/audit", string(body)))
	if len(got.Findings) != 1 {
		t.Fatal("expected one contextual finding")
	}
	f := got.Findings[0]
	if f.Type != "SECRET" || f.Rule != "keyword:password" || string([]rune(text)[f.Start:f.End]) != "Tr0u\u200bb4dor&3x" || got.Texts[0] != text {
		t.Fatal("original finding contract")
	}
}

func TestNativeSecretTypedMaskAndOverlaps(t *testing.T) {
	dir := t.TempDir()
	catalog := `version: 1
policies:
 - name: detect_secret
   mode: enforce
   stages:
     input:
       - detector: detect_secret
         action: mask
         mask: "[{TYPE}]"
     output:
       - detector: detect_secret
         action: mask
         mask: "[{TYPE}]"
`
	if err := os.WriteFile(filepath.Join(dir, "policies.yaml"), []byte(catalog), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := app.NewHandler(config.Config{GuardrailsConfigDir: dir, LiteLLMDefaultPolicy: "detect_secret", SecretMask: "[REDACTED]", MaxTextItems: 20, MaxTextChars: 20000})
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"request", "response"} {
		body, _ := json.Marshal(map[string]any{"texts": []string{"🙂 password=ghp_Ab3dEf7hIj9lMn2pQr4tUv6xYz8BcDeFgHiJ", "q7V9m2Z4r8B1n6C3x5K0pA+e/DfGhJkL"}, "input_type": stage})
		got := decodePolicy(t, post(t, h, "/v1/guardrails/detect_secret", string(body)))
		if len(got.Findings) != 2 || got.Texts[0] != "🙂 password=[SECRET]" || got.Texts[1] != "[HIGH_ENTROPY_STRING]" || got.Findings[1].Score == nil {
			t.Fatal("typed masks, overlap precedence or entropy score contract")
		}
	}
}
