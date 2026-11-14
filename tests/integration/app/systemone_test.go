package app_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/internal/semantic/httpclassifier"
	"github.com/g1lom/guardrail-serve/internal/semantic/systemone"
)

const integrationJudgeKey = "ts-integration-key-91c2"

func setSystemOneEnv(t *testing.T, values map[string]string) {
	t.Helper()
	for _, key := range []string{
		"SEMANTIC_ENABLED", "SEMANTIC_URL", "SEMANTIC_FORMAT", "SEMANTIC_FAILURE_MODE",
		"SYSTEMONE_ENABLED", "SYSTEMONE_MODE", "SYSTEMONE_BASE_URL", "SYSTEMONE_MODEL", "SYSTEMONE_API_KEY",
		"SYSTEMONE_API_KEY_FILE", "SYSTEMONE_QUESTION", "SYSTEMONE_THRESHOLD", "SYSTEMONE_ZONE_LOWER",
		"SYSTEMONE_ZONE_UPPER", "SYSTEMONE_TIMEOUT", "SYSTEMONE_FAILURE_MODE", "SYSTEMONE_MAX_TEXT_RUNES",
	} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
}

func TestSystemOneStartupValidation(t *testing.T) {
	base := map[string]string{
		"SEMANTIC_ENABLED": "true", "SEMANTIC_URL": "http://127.0.0.1:1/classify",
		"SYSTEMONE_ENABLED": "true", "SYSTEMONE_BASE_URL": "https://api.typesafe.ai", "SYSTEMONE_MODEL": "jev-1.14.0",
		"SYSTEMONE_API_KEY": integrationJudgeKey, "SYSTEMONE_ZONE_LOWER": "0.3", "SYSTEMONE_ZONE_UPPER": "0.9",
	}
	with := func(changes map[string]string) map[string]string {
		values := map[string]string{}
		for k, v := range base {
			values[k] = v
		}
		for k, v := range changes {
			if v == "-" {
				delete(values, k)
			} else {
				values[k] = v
			}
		}
		return values
	}
	setSystemOneEnv(t, base)
	if _, err := app.NewHandler(config.Load()); err != nil {
		t.Fatalf("valid cascade configuration rejected: %v", err)
	}
	for name, changes := range map[string]map[string]string{
		"cascade without primary": {"SEMANTIC_ENABLED": "-", "SEMANTIC_URL": "-"},
		"judge only with primary": {"SYSTEMONE_MODE": "judge_only"},
		"inverted zone":           {"SYSTEMONE_ZONE_LOWER": "0.95"},
		"missing zone":            {"SYSTEMONE_ZONE_UPPER": "-"},
		"remote http":             {"SYSTEMONE_BASE_URL": "http://api.typesafe.ai"},
		"credentials in URL":      {"SYSTEMONE_BASE_URL": "https://user:" + integrationJudgeKey + "@api.typesafe.ai"},
		"missing model":           {"SYSTEMONE_MODEL": "-"},
		"missing key":             {"SYSTEMONE_API_KEY": "-"},
		"unknown question":        {"SYSTEMONE_QUESTION": "box"},
		"unknown failure mode":    {"SYSTEMONE_FAILURE_MODE": "maybe"},
		"threshold out of range":  {"SYSTEMONE_THRESHOLD": "0"},
	} {
		t.Run(name, func(t *testing.T) {
			setSystemOneEnv(t, with(changes))
			_, err := app.NewHandler(config.Load())
			if err == nil {
				t.Fatal("invalid configuration accepted")
			}
			if strings.Contains(err.Error(), integrationJudgeKey) {
				t.Fatalf("startup error leaks the key: %v", err)
			}
		})
	}
	t.Run("disabled by default", func(t *testing.T) {
		setSystemOneEnv(t, nil)
		dir := t.TempDir()
		writeOverride(t, dir, "policies.yaml", "version: 1\npolicies:\n  - name: s\n    mode: enforce\n    stages:\n      input:\n        - detector: semantic_prompt_injection\n          action: block\n      output: []\n")
		cfg := config.Load()
		cfg.GuardrailsConfigDir, cfg.LiteLLMDefaultPolicy = dir, "s"
		if _, err := app.NewHandler(cfg); err == nil || !strings.Contains(err.Error(), "semantic_prompt_injection") {
			t.Fatalf("an unregistered semantic detector must fail startup: %v", err)
		}
	})
}

// TestSystemOneMaskingFollowsOverridesWithoutLosingDefaults checks that operator
// pattern overrides add judge masking coverage but never remove the defaults.
func TestSystemOneMaskingFollowsOverridesWithoutLosingDefaults(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	judge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		_, _ = io.WriteString(w, `{"model":"jev-1.14.0","answers":{"prompt_injection":{"type":"noul","noul":0.1}},"usage":{"input_tokens":10,"output_tokens":1}}`)
	}))
	defer judge.Close()
	key, err := systemone.NewAPIKey(integrationJudgeKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeOverride(t, dir, "policies.yaml", "version: 1\npolicies:\n  - name: s\n    mode: enforce\n    stages:\n      input:\n        - detector: semantic_prompt_injection\n          action: annotate\n      output: []\n")
	// The PII override drops every default rule; the secret override is empty.
	writeOverride(t, dir, "detect_pii_patterns.yaml", "patterns:\n  - name: badge\n    type: BADGE_ID\n    regex: '(?P<secret>B-\\d{4})'\n")
	writeOverride(t, dir, "detect_secret_contextual_patterns.yaml", "patterns: []\n")
	cfg := policyConfig(dir, "s")
	cfg.Runtime.MaxConcurrentRequests = 8
	cfg.SystemOne = config.SystemOne{Enabled: true, Mode: systemone.ModeJudgeOnly, Judge: systemone.Config{
		BaseURL: judge.URL, Model: "jev-1.14.0", APIKey: key, Question: systemone.QuestionNoul,
		Threshold: 0.7, Timeout: time.Second, FailureMode: httpclassifier.FailClosed,
	}}
	handler, err := app.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	text := "badge B-1234, mail chloé.martin@exemple.fr, token=ghp_Ab3dEf7hIj9lMn2pQr4tUv6xYz8BcDeFgHiJ"
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload, _ := json.Marshal(map[string]any{"texts": []string{text}})
			resp, err := http.Post(server.URL+"/v1/guardrails/s", "application/json", strings.NewReader(string(payload)))
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Errorf("status %d", resp.StatusCode)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 8 {
		t.Fatalf("judge requests: %d", len(bodies))
	}
	for _, body := range bodies {
		for _, leaked := range []string{"B-1234", "chlo", "martin", "exemple.fr", "ghp_"} {
			if strings.Contains(body, leaked) {
				t.Fatalf("judge body leaks %q: %s", leaked, body)
			}
		}
		for _, mask := range []string{"[BADGE_ID]", "[EMAIL]", "[SECRET]"} {
			if !strings.Contains(body, mask) {
				t.Fatalf("judge body lacks %s: %s", mask, body)
			}
		}
	}
}
