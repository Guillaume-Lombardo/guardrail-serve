package observability

import (
	"net/http"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/policy"
	"github.com/g1lom/guardrail-serve/internal/semantic/systemone"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics adapts engine observations to a private Prometheus registry.
// Label allowlists are copied at construction and never mutated afterwards.
type Metrics struct {
	policies, detectors map[string]bool
	executions          *prometheus.CounterVec
	duration            *prometheus.HistogramVec
	judgeRoutes         *prometheus.CounterVec
	judgments           *prometheus.CounterVec
	judgmentDuration    *prometheus.HistogramVec
	judgeInputTokens    *prometheus.CounterVec
	handler             http.Handler
}

var _ systemone.Observer = (*Metrics)(nil)

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
	m.judgeRoutes = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "guardrail_systemone_routes_total", Help: "Cascade evaluations by deciding route (judged, below_zone, above_zone, primary_failure, empty)."}, []string{"route"})
	m.judgments = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "guardrail_systemone_judgments_total", Help: "System One judgments per text by outcome; failures before sending (masking_failed, text_too_large) make no request."}, []string{"outcome"})
	m.judgmentDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "guardrail_systemone_judgment_duration_seconds", Help: "System One judgment duration in seconds, masking included.", Buckets: prometheus.DefBuckets}, []string{"outcome"})
	// A label-free vector exports no series until the first judgment, like the other collectors.
	m.judgeInputTokens = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "guardrail_systemone_input_tokens_total", Help: "Billable input tokens reported by successful System One responses."}, nil)
	collectors := []prometheus.Collector{m.executions, m.duration, m.judgeRoutes, m.judgments, m.judgmentDuration, m.judgeInputTokens}
	for i, collector := range collectors {
		if err := registry.Register(collector); err != nil {
			for _, registered := range collectors[:i] {
				registry.Unregister(registered)
			}
			return nil, err
		}
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

// ObserveJudgment records one System One judgment; labels come from fixed enumerations.
func (m *Metrics) ObserveJudgment(j systemone.Judgment) {
	outcome := "unknown"
	for _, candidate := range systemone.Outcomes() {
		if j.Outcome == candidate {
			outcome = string(candidate)
		}
	}
	m.judgments.WithLabelValues(outcome).Inc()
	m.judgmentDuration.WithLabelValues(outcome).Observe(j.Duration.Seconds())
	if j.InputTokens > 0 {
		m.judgeInputTokens.WithLabelValues().Add(float64(j.InputTokens))
	}
}

// ObserveRoute records which component decided one cascade evaluation.
func (m *Metrics) ObserveRoute(route systemone.Route) {
	label := "unknown"
	for _, candidate := range systemone.Routes() {
		if route == candidate {
			label = string(candidate)
		}
	}
	m.judgeRoutes.WithLabelValues(label).Inc()
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) { m.handler.ServeHTTP(w, r) }
