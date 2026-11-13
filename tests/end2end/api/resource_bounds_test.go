package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
)

func TestRealHTTPBodyBoundary(t *testing.T) {
	cfg := config.Load()
	h, err := app.NewHandlerWithLogger(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	for _, path := range []string{"/scan/secrets", "/v1/guardrails/default", "/beta/litellm_basic_guardrail_api"} {
		for _, unknown := range []bool{false, true} {
			for _, size := range []int{1048575, 1048576, 1048577} {
				payload := `{"texts":["ok"],"input_type":"request"}`
				body := payload + strings.Repeat(" ", size-len(payload))
				var reader io.Reader = strings.NewReader(body)
				if unknown {
					reader = struct{ io.Reader }{reader}
				}
				r, err := http.NewRequest("POST", srv.URL+path, reader)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Content-Type", "application/json")
				res, err := srv.Client().Do(r)
				if err != nil {
					t.Fatal(err)
				}
				b, _ := io.ReadAll(res.Body)
				res.Body.Close()
				want := 200
				if size > 1048576 {
					want = 413
				}
				if res.StatusCode != want {
					t.Errorf("%s unknown=%v size=%d: %d %s", path, unknown, size, res.StatusCode, b)
				}
				if want == 413 && strings.TrimSpace(string(b)) != `{"detail":"Request body too large."}` {
					t.Errorf("unstable 413: %s", b)
				}
			}
		}
	}
}

func TestHealthLogAndEchoBounds(t *testing.T) {
	var logs bytes.Buffer
	cfg := config.Load()
	cfg.Runtime.APIKeys = []string{"key"}
	h, err := app.NewHandlerWithLogger(cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"compatible.ID_123-ok", strings.Repeat("x", 9000)} {
		logs.Reset()
		r := httptest.NewRequest("GET", "/health/", nil)
		r.Header.Set("X-Request-ID", id)
		r.Header.Set("User-Agent", strings.Repeat("界", 1000))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		echo := w.Header().Get("X-Request-ID")
		if w.Code != 200 || len(echo) > 128 || echo == "" {
			t.Fatalf("invalid health response: %d id length %d", w.Code, len(echo))
		}
		if len(id) <= 128 && echo != id {
			t.Error("compatible id changed")
		}
		var entry map[string]any
		if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
			t.Fatal(err)
		}
		if entry["request_id"] != echo || len(entry["user_agent"].(string)) > 256 {
			t.Error("log metadata not bounded")
		}
	}
}
