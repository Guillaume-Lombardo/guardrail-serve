package app_test

import (
	"github.com/g1lom/guardrail-serve/internal/app"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizedOverrideGraphemeOverlaps(t *testing.T) {
	dir := t.TempDir()
	writeOverride(t, dir, "policies.yaml", overridePolicies)
	writeOverride(t, dir, "detect_pii_patterns.yaml", `patterns:
  - name: f
    type: LETTER
    regex: '(?P<secret>f)'
  - name: i
    type: LETTER
    regex: '(?P<secret>i)'
  - name: accent
    type: ACCENT
    regex: '(?P<secret>é)'
`)
	h, err := app.NewHandler(policyConfig(dir, "tenant-a"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(http.MethodPost, "/v1/guardrails/tenant-a", strings.NewReader(`{"texts":["🙂 ﬁ é"]}`)))
		if r.Code != 200 || !strings.Contains(r.Body.String(), `"texts":["🙂 <LETTER> <ACCENT>"]`) || strings.Count(r.Body.String(), `"start":2,"end":3`) != 2 || !strings.Contains(r.Body.String(), `"start":4,"end":6`) {
			t.Fatalf("%d %s", r.Code, r.Body.String())
		}
	}
}

func TestUnknownPIIValidatorFailsStartup(t *testing.T) {
	dir := t.TempDir()
	writeOverride(t, dir, "detect_pii_patterns.yaml", `patterns:
  - name: invalid
    validator: unknown
    regex: '(?P<secret>.+)'
`)
	if _, err := app.NewHandler(policyConfig(dir, "default")); err == nil {
		t.Fatal("unknown validator accepted")
	}
}
