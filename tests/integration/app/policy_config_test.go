package app_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
)

func writeOverride(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func policyConfig(dir, litellm string) config.Config {
	return config.Config{SecretMask: "[REDACTED]", GuardrailsConfigDir: dir, LiteLLMDefaultPolicy: litellm, MaxTextItems: 20, MaxTextChars: 20000}
}

const overridePolicies = `version: 1
policies:
  - name: tenant-a
    mode: enforce
    stages:
      input:
        - detector: detect_pii
          action: mask
          mask: "<{TYPE}>"
      output: []
`

func TestPolicyOverrideReplacesCatalogAndDrivesRoutes(t *testing.T) {
	dir := t.TempDir()
	writeOverride(t, dir, "policies.yaml", overridePolicies)
	writeOverride(t, dir, "detect_pii_patterns.yaml", "patterns:\n  - name: badge\n    type: BADGE_ID\n    regex: '(?P<secret>B-\\d{4})'\n")
	handler, err := app.NewHandler(policyConfig(dir, "tenant-a"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ path, body, want string }{
		{"/v1/guardrails/tenant-a", `{"texts":["badge B-1234"]}`, `"texts":["badge <BADGE_ID>"]`},
		{"/v1/guardrails/tenant-a", `{"texts":["badge B-1234"],"input_type":"response"}`, `"texts":["badge B-1234"]`},
		{"/beta/litellm_basic_guardrail_api", `{"texts":["badge B-1234"]}`, `"texts":["badge <BADGE_ID>"]`},
		// /scan routes are fixed: the policy override never changes them.
		{"/scan/pii", `{"texts":["badge B-1234"]}`, `"texts":["badge [REDACTED]"]`},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body)))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), tc.want) {
			t.Fatalf("%s %s: status=%d body=%s, want %s", tc.path, tc.body, recorder.Code, recorder.Body.String(), tc.want)
		}
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/guardrails/default", strings.NewReader(`{"texts":["x"]}`)))
	var response map[string]string
	_ = json.Unmarshal(recorder.Body.Bytes(), &response)
	if recorder.Code != http.StatusNotFound || response["detail"] != "Unknown policy 'default'." {
		t.Fatalf("embedded policies must not leak through an override: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestInvalidPolicyConfigurationFailsStartup(t *testing.T) {
	for _, tc := range []struct {
		name, policies, litellm, want string
	}{
		{"unknown detector", strings.Replace(overridePolicies, "detect_pii", "detect_magic", 1), "tenant-a", `unknown detector "detect_magic"`},
		{"unknown action", strings.Replace(overridePolicies, "action: mask", "action: redact", 1), "tenant-a", `unknown action "redact"`},
		{"unknown mode", strings.Replace(overridePolicies, "mode: enforce", "mode: shadow", 1), "tenant-a", `unknown mode "shadow"`},
		{"invalid yaml", "version: [", "tenant-a", "decode"},
		{"undefined LiteLLM default", overridePolicies, "default", `LITELLM_DEFAULT_POLICY "default" is not defined`},
		{"legacy LiteLLM name absent from override", overridePolicies, "", `LITELLM_DEFAULT_POLICY "detect_secret" is not defined`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeOverride(t, dir, "policies.yaml", tc.policies)
			_, err := app.NewHandler(policyConfig(dir, tc.litellm))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			if tc.name != "undefined LiteLLM default" && tc.name != "legacy LiteLLM name absent from override" && !strings.Contains(err.Error(), filepath.Join(dir, "policies.yaml")) {
				t.Fatalf("error must name the override file: %v", err)
			}
		})
	}

	if _, err := app.NewHandler(policyConfig("", "missing")); err == nil || !strings.Contains(err.Error(), "embedded defaults/policies.yaml") {
		t.Fatalf("unknown default against embedded catalog: %v", err)
	}
}

func TestEmbeddedCatalogKeepsLegacyLiteLLMNames(t *testing.T) {
	for _, name := range []string{"detect_secret", "detect_pii", "prompt_injection", "max_length", "default", "audit"} {
		if _, err := app.NewHandler(policyConfig("", name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestDisabledSemanticPolicyFailsStartup(t *testing.T) {
	dir := t.TempDir()
	writeOverride(t, dir, "policies.yaml", strings.ReplaceAll(overridePolicies, "detect_pii", "semantic_prompt_injection"))
	_, err := app.NewHandler(policyConfig(dir, "tenant-a"))
	if err == nil || !strings.Contains(err.Error(), `unknown detector "semantic_prompt_injection"`) {
		t.Fatalf("disabled detector: %v", err)
	}
}
