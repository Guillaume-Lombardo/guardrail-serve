package api_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/internal/semantic/httpclassifier"
)

const semanticPolicy = `version: 1
policies:
  - name: semantic
    mode: enforce
    stages:
      input:
        - detector: prompt_injection
          action: annotate
        - detector: semantic_prompt_injection
          action: block
      output:
        - detector: semantic_prompt_injection
          action: annotate
`

func TestSemanticHTTPJourney(t *testing.T) {
	for _, format := range []httpclassifier.Format{httpclassifier.FormatScores, httpclassifier.FormatTEIPredict} {
		for _, failure := range []string{"", "closed", "open", "clean"} {
			for _, policyMode := range []string{"enforce", "detect"} {
				t.Run(string(format)+failure+policyMode, func(t *testing.T) {
					calls := 0
					sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls++
						if r.Method != "POST" || r.URL.Path != "/predict" || r.Header.Get("Authorization") != "" {
							t.Error("unexpected sidecar request")
						}
						var body map[string]json.RawMessage
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
							t.Error(err)
						}
						key := "texts"
						if format == httpclassifier.FormatTEIPredict {
							key = "inputs"
						}
						var texts []json.RawMessage
						if err := json.Unmarshal(body[key], &texts); err != nil || len(texts) != 1 {
							t.Errorf("wire contract: %s", body)
						}
						if failure == "closed" || failure == "open" {
							w.WriteHeader(503)
							_, _ = w.Write([]byte("private-provider-content"))
							return
						}
						score := "0.9"
						if failure == "clean" {
							score = "0.89"
						}
						w.Header().Set("Content-Type", "application/json")
						if format == httpclassifier.FormatScores {
							_, _ = w.Write([]byte(`{"scores":[` + score + `]}`))
						} else {
							_, _ = w.Write([]byte(`[[{"label":"ATTACK","score":` + score + `},{"label":"BENIGN","score":0.1}]]`))
						}
					}))
					defer sidecar.Close()
					dir := t.TempDir()
					if err := os.WriteFile(filepath.Join(dir, "policies.yaml"), []byte(strings.Replace(semanticPolicy, "mode: enforce", "mode: "+policyMode, 1)), 0600); err != nil {
						t.Fatal(err)
					}
					mode := httpclassifier.FailClosed
					if failure == "open" {
						mode = httpclassifier.FailOpen
					}
					cfg := config.Config{SecretMask: "[REDACTED]", GuardrailsConfigDir: dir, LiteLLMDefaultPolicy: "semantic", MaxTextItems: 20, MaxTextChars: 20000,
						Runtime:  config.Runtime{APIKeys: []string{"test-key"}},
						Semantic: config.Semantic{Enabled: true, HTTP: httpclassifier.Config{URL: sidecar.URL + "/predict", Format: format, Threshold: 0.9, Timeout: time.Second, FailureMode: mode, MaliciousLabels: []string{"ATTACK"}}}}
					var logs bytes.Buffer
					handler, err := app.NewHandlerWithLogger(cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
					if err != nil {
						t.Fatal(err)
					}
					server := httptest.NewServer(handler)
					defer server.Close()
					text := "é🙂 sample"
					for _, route := range []string{"/v1/guardrails/semantic", "/beta/litellm_basic_guardrail_api"} {
						for _, scope := range []string{"request", "response"} {
							envelope := map[string]any{"texts": []string{"", text}, "input_type": scope, "request_headers": map[string]string{"Authorization": "untrusted"}, "request_data": map[string]string{"url": "http://untrusted.invalid"}}
							if !strings.Contains(route, "litellm") {
								delete(envelope, "request_headers")
							}
							body, _ := json.Marshal(envelope)
							req, _ := http.NewRequest("POST", server.URL+route, bytes.NewReader(body))
							req.Header.Set("Authorization", "Bearer test-key")
							resp, err := server.Client().Do(req)
							if err != nil {
								t.Fatal(err)
							}
							var result map[string]any
							err = json.NewDecoder(resp.Body).Decode(&result)
							resp.Body.Close()
							if err != nil {
								t.Fatal(err)
							}
							if failure == "closed" {
								if resp.StatusCode != 502 || result["detail"] != "Guardrail execution failed." {
									t.Fatalf("closed: %d %v", resp.StatusCode, result)
								}
								continue
							}
							if resp.StatusCode != 200 {
								t.Fatalf("%d %v", resp.StatusCode, result)
							}
							if strings.Contains(route, "litellm") {
								action := "NONE"
								if failure == "" && scope == "request" && policyMode == "enforce" {
									action = "BLOCKED"
								}
								if result["action"] != action || len(result) > 3 {
									t.Fatalf("LiteLLM: %v", result)
								}
							} else if failure == "" {
								findings, ok := result["findings"].([]any)
								if !ok || len(findings) != 1 {
									t.Fatalf("findings: %v", result)
								}
								f := findings[0].(map[string]any)
								if f["text_index"] != float64(1) || f["start"] != float64(0) || f["end"] != float64(utf8.RuneCountInString(text)) || f["score"] != 0.9 {
									t.Fatalf("span/score: %v", f)
								}
							}
						}
					}
					if calls != 4 {
						t.Fatalf("calls=%d", calls)
					}
					if failure == "open" && !strings.Contains(logs.String(), "semantic classifier degraded") {
						t.Fatal("missing degradation signal")
					}
					if strings.Contains(logs.String(), text) || strings.Contains(logs.String(), sidecar.URL) || strings.Contains(logs.String(), "private-provider-content") {
						t.Fatal("unsafe log")
					}
					req, _ := http.NewRequest("GET", server.URL+"/metrics", nil)
					req.Header.Set("Authorization", "Bearer test-key")
					resp, err := server.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					var metrics bytes.Buffer
					_, _ = metrics.ReadFrom(resp.Body)
					resp.Body.Close()
					outcome := "match"
					if failure == "closed" {
						outcome = "error"
					}
					if failure == "open" || failure == "clean" {
						outcome = "clean"
					}
					if !strings.Contains(metrics.String(), `detector="semantic_prompt_injection"`) || !strings.Contains(metrics.String(), `outcome="`+outcome+`"`) {
						t.Fatalf("metrics missing: %s", metrics.String())
					}
					resp, err = server.Client().Post(server.URL+"/v1/guardrails/semantic", "application/json", strings.NewReader(`{"texts":["x"]}`))
					if err != nil {
						t.Fatal(err)
					}
					resp.Body.Close()
					if resp.StatusCode != 401 || calls != 4 {
						t.Fatal("authentication bypass")
					}
				})
			}
		}
	}
}
