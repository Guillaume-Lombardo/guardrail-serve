package api_test

import (
	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRuntimeAuthAndBodyLimits(t *testing.T) {
	cfg := config.Config{APIPrefix: "/v1", MaxTextItems: 20, MaxTextChars: 3, SecretMask: "[REDACTED]", Runtime: config.Runtime{APIKeys: []string{"first-key", "second-key"}, MaxBodyBytes: 128}}
	h, err := app.NewHandlerWithLogger(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, auth, key, body string
		status                      int
		duplicate                   bool
	}{
		{name: "missing", path: "/v1/scan/secrets", status: 401},
		{name: "invalid", path: "/v1/scan/secrets", key: "invalid", status: 401},
		{name: "first", path: "/v1/scan/secrets", auth: "Bearer first-key", body: `{"texts":["é界🙂"],"input_type":"request"}`, status: 200},
		{name: "second", path: "/v1/scan/secrets", key: "second-key", body: `{"texts":["é界🙂"],"input_type":"request"}`, status: 200},
		{name: "both", path: "/v1/scan/secrets", auth: "Bearer first-key", key: "second-key", status: 401},
		{name: "duplicate", path: "/v1/scan/secrets", key: "first-key", duplicate: true, status: 401},
		{name: "health", path: "/v1/health/", status: 200},
		{name: "health-prefix", path: "/health/", status: 401},
		{name: "docs", path: "/v1/docs", status: 401},
		{name: "oversized", path: "/v1/scan/secrets", key: "first-key", body: strings.Repeat("x", 129), status: 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method := http.MethodPost
			if strings.Contains(tc.name, "health") || tc.name == "docs" {
				method = http.MethodGet
			}
			r := httptest.NewRequest(method, tc.path, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/json")
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			if tc.key != "" {
				r.Header.Set("X-API-Key", tc.key)
			}
			if tc.duplicate {
				r.Header.Add("X-API-Key", tc.key)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if tc.status == 200 && tc.name != "health" && strings.Contains(w.Body.String(), "BLOCKED") {
				t.Fatal("Unicode text unexpectedly blocked")
			}
			if tc.status == 401 && strings.Contains(w.Body.String(), "key") {
				t.Fatal("credential leaked")
			}
		})
	}
	cfg.Runtime.APIKeys = nil
	h, err = app.NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/scan/secrets", strings.NewReader(`{"texts":["ok"],"input_type":"request"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("disabled auth status: %d", w.Code)
	}
}
