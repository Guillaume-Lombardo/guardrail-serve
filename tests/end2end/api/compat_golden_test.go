package api_test

import (
	"encoding/json"
	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// testdata/compat_golden.json was recorded from the pre-policy-engine
// implementation (main 6eeac11). /scan/* and the default LiteLLM policy must
// retain these results when the explicit legacy secrets override is used.
func TestScanAndLiteLLMMatchPrePolicyEngineGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/compat_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Route    string          `json:"route"`
		Body     json.RawMessage `json:"body"`
		Status   int             `json:"status"`
		Response any             `json:"response"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty golden corpus")
	}
	dir := t.TempDir()
	legacy, err := os.ReadFile("testdata/legacy_secret_patterns.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "detect_secret_contextual_patterns.yaml"), legacy, 0600); err != nil {
		t.Fatal(err)
	}
	handler, err := app.NewHandler(config.Config{GuardrailsConfigDir: dir, SecretMask: "[REDACTED]", LiteLLMDefaultPolicy: "detect_secret", MaxTextItems: 20, MaxTextChars: 20000})
	if err != nil {
		t.Fatal(err)
	}
	for index, tc := range cases {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, tc.Route, strings.NewReader(string(tc.Body))))
		var got any
		if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
			t.Fatalf("case %d: decode: %v", index, err)
		}
		if recorder.Code != tc.Status || !reflect.DeepEqual(got, tc.Response) {
			t.Errorf("case %d %s: status=%d body=%s, want status=%d %v", index, tc.Route, recorder.Code, recorder.Body.String(), tc.Status, tc.Response)
		}
	}
}
