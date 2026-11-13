package app_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/guardrails"
	"github.com/g1lom/guardrail-serve/internal/httpapi"
	"github.com/g1lom/guardrail-serve/internal/observability"
	"github.com/g1lom/guardrail-serve/internal/policy"
	"github.com/prometheus/client_golang/prometheus"
)

type failingMetricDetector struct{ invalid bool }

func (d failingMetricDetector) Name() string               { return "failure" }
func (d failingMetricDetector) Supports(domain.Stage) bool { return true }
func (d failingMetricDetector) BlockReason() string        { return "blocked" }
func (d failingMetricDetector) Detect(ctx context.Context, _ string) ([]domain.Detection, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if d.invalid {
		return []domain.Detection{{Start: 0, End: 100}}, nil
	}
	return nil, errors.New("sensitive-error")
}
func TestMetricsHTTPDetectorErrorsAndCancellation(t *testing.T) {
	for _, kind := range []string{"error", "invalid-span", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			p, err := policy.NewPolicy("failure", domain.ModeEnforce, []policy.Step{{Detector: failingMetricDetector{invalid: kind == "invalid-span"}, Action: domain.ActionBlock}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			catalog, _ := policy.NewCatalog(p)
			registry := prometheus.NewRegistry()
			metrics, err := observability.NewMetrics(registry, []string{p.Name}, []string{"failure", "max_length"})
			if err != nil {
				t.Fatal(err)
			}
			engine := policy.NewEngineWithObserver(guardrails.NewMaxLengthGuardrail(10, 1000), metrics)
			cfg := config.Load()
			cfg.LiteLLMDefaultPolicy = p.Name
			h := httpapi.NewHandler(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), engine, catalog, httpapi.ScanPolicies{Secrets: p, PII: p, PromptInjection: p})
			mux := http.NewServeMux()
			h.Register(mux)
			r := httptest.NewRequest("POST", "/v1/guardrails/failure", strings.NewReader(`{"texts":["private-text"]}`))
			if kind == "cancel" {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != 502 {
				t.Fatalf("got %d %s", w.Code, w.Body.String())
			}
			families, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range families {
				errorsCount := 0
				for _, m := range f.Metric {
					for _, pair := range m.Label {
						if pair.GetName() == "outcome" && pair.GetValue() == "error" {
							errorsCount++
						}
					}
				}
				if errorsCount != 2 {
					t.Fatalf("%s: error series %d", f.GetName(), errorsCount)
				}
			}
		})
	}
}
