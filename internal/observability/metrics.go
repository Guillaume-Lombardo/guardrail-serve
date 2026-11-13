package observability

import (
	"net/http"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/policy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics adapts engine observations to a private Prometheus registry.
// Label allowlists are copied at construction and never mutated afterwards.
type Metrics struct {
	policies, detectors map[string]bool
	executions          *prometheus.CounterVec
	duration            *prometheus.HistogramVec
	handler             http.Handler
}

// NewMetrics accepts a caller-owned registry; nil creates a fresh registry.
// Reusing a registry with these metric names returns a registration error.
func NewMetrics(registry *prometheus.Registry, policies, detectors []string) (*Metrics, error) {
	if registry == nil {
		registry = prometheus.NewRegistry()
	}
	m := &Metrics{policies: nameSet(policies), detectors: nameSet(detectors)}
	labels := []string{"policy", "mode", "stage", "detector", "action", "decision", "outcome"}
	m.executions = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "guardrail_executions_total", Help: "Completed policy evaluations (detector=none) and detector calls (per text, limits per evaluation)."}, labels)
	m.duration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "guardrail_execution_duration_seconds", Help: "Policy evaluation or detector call duration in seconds.", Buckets: prometheus.DefBuckets}, labels)
	if err := registry.Register(m.executions); err != nil {
		return nil, err
	}
	if err := registry.Register(m.duration); err != nil {
		registry.Unregister(m.executions)
		return nil, err
	}
	// HandlerFor does not install scrape instrumentation or use global collectors.
	m.handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	return m, nil
}

func nameSet(names []string) map[string]bool {
	result := make(map[string]bool, len(names))
	for _, name := range names {
		result[name] = true
	}
	return result
}
func bounded(value string, allowed map[string]bool) string {
	if allowed[value] {
		return value
	}
	return "unknown"
}
func choice(value string, allowed ...string) string {
	for _, candidate := range allowed {
		if value == candidate {
			return value
		}
	}
	return "unknown"
}

func (m *Metrics) Observe(o policy.Observation) {
	detector, action, decision := "none", "none", "none"
	if o.Detector != "" {
		detector = bounded(o.Detector, m.detectors)
		action = choice(string(o.Action), string(domain.ActionBlock), string(domain.ActionMask), string(domain.ActionAnnotate))
	} else if o.Outcome != policy.OutcomeError {
		decision = choice(string(o.Decision), string(domain.DecisionNone), string(domain.DecisionBlocked), string(domain.DecisionGuardrailIntervened))
	}
	labels := []string{bounded(o.Policy, m.policies), choice(string(o.Mode), "enforce", "detect"), choice(string(o.Stage), "input", "output"), detector, action, decision, choice(string(o.Outcome), "clean", "match", "error")}
	m.executions.WithLabelValues(labels...).Inc()
	m.duration.WithLabelValues(labels...).Observe(o.Duration.Seconds())
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.handler.ServeHTTP(w, r) }
