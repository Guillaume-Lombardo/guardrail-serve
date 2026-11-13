package observability_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/observability"
	"github.com/g1lom/guardrail-serve/internal/policy"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMetricsBoundedConcurrentAndRegistry(t *testing.T) {
	registry := prometheus.NewRegistry()
	m, err := observability.NewMetrics(registry, []string{"known"}, []string{"detector"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observability.NewMetrics(registry, nil, nil); err == nil {
		t.Fatal("duplicate registry accepted")
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sensitive := fmt.Sprintf("sensitive-%d", i)
			m.Observe(policy.Observation{Policy: sensitive, Mode: domain.Mode(sensitive), Stage: domain.Stage(sensitive), Detector: sensitive, Action: domain.Action(sensitive), Decision: domain.Decision(sensitive), Outcome: policy.Outcome(sensitive), Duration: time.Millisecond})
		}(i)
	}
	wg.Wait()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if len(f.Metric) != 1 {
			t.Fatalf("unbounded series: %s %d", f.GetName(), len(f.Metric))
		}
		for _, pair := range f.Metric[0].Label {
			if pair.GetValue() != "unknown" && pair.GetValue() != "none" {
				t.Fatalf("unbounded label %v", pair)
			}
		}
		if f.GetName() == "guardrail_executions_total" && f.Metric[0].Counter.GetValue() != 100 {
			t.Fatal("lost increments")
		}
		if f.GetName() == "guardrail_execution_duration_seconds" && f.Metric[0].Histogram.GetSampleCount() != 100 {
			t.Fatal("lost observations")
		}
	}
}
