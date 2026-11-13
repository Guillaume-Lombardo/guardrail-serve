package eval

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// Mode selects what the harness observes.
type Mode string

const (
	// ModeAnnotate evaluates findings reported by a policy through
	// POST /v1/guardrails/{policy}: one request per case, every labelled
	// detector read from the same response.
	ModeAnnotate Mode = "annotate"
	// ModeEnforce evaluates decisions through the single-detector /scan
	// routes: one request per labelled detector, detected means the decision
	// is not NONE.
	ModeEnforce Mode = "enforce"
)

// ParseMode validates a mode.
func ParseMode(value string) (Mode, error) {
	switch Mode(value) {
	case ModeAnnotate, ModeEnforce:
		return Mode(value), nil
	}
	return "", fmt.Errorf("mode must be %q or %q, got %q", ModeAnnotate, ModeEnforce, value)
}

// Status is the outcome of a run.
type Status string

const (
	// StatusComplete: every request succeeded.
	StatusComplete Status = "complete"
	// StatusCompleteWithErrors: every case was attempted, some requests failed.
	StatusCompleteWithErrors Status = "complete_with_errors"
	// StatusAborted: the run stopped early; results are partial.
	StatusAborted Status = "aborted"
)

// DefaultMaxConsecutiveErrors stops a run against an unreachable service.
const DefaultMaxConsecutiveErrors = 5

// RunConfig configures a run.
type RunConfig struct {
	Mode Mode
	// Policy is the policy evaluated in annotate mode.
	Policy string
	// MaxConsecutiveErrors aborts after that many request errors in a row;
	// zero disables the check. Limit blocks are data errors and do not count.
	MaxConsecutiveErrors int
}

// Validate checks the configuration against the corpora before any request.
func (cfg RunConfig) Validate(corpora []*Corpus) error {
	switch cfg.Mode {
	case ModeAnnotate:
		if !policyNamePattern.MatchString(cfg.Policy) {
			return fmt.Errorf("policy %q must match %s", cfg.Policy, policyNamePattern)
		}
	case ModeEnforce:
		for _, corpus := range corpora {
			for _, detector := range corpus.Detectors() {
				if _, ok := ScanRouteFor(detector); !ok {
					return fmt.Errorf("corpus %q labels detector %q, which has no /scan route; use --mode annotate", corpus.Header.Name, detector)
				}
			}
		}
	default:
		return fmt.Errorf("unsupported mode %q", cfg.Mode)
	}
	if cfg.MaxConsecutiveErrors < 0 {
		return errors.New("max consecutive errors must not be negative")
	}
	return nil
}

// RequestFailure is one failed evaluation. It never contains the text.
type RequestFailure struct {
	Corpus string
	CaseID string
	// Detector is set in enforce mode, where each request targets one detector.
	Detector string
	Kind     ErrorKind
	Status   int
	Message  string
}

// tally accumulates one detector's outcomes within one corpus.
type tally struct {
	total  Confusion
	byLang map[string]*Confusion
	byTag  map[string]*Confusion
	// errored counts labelled evaluations that produced no observation.
	errored int
}

func newTally() *tally {
	return &tally{byLang: map[string]*Confusion{}, byTag: map[string]*Confusion{}}
}

func (t *tally) observe(item Case, expected, detected bool) {
	t.total.Add(expected, detected)
	addTo(t.byLang, item.Lang, expected, detected)
	for _, tag := range item.Tags {
		addTo(t.byTag, tag, expected, detected)
	}
}

func addTo(groups map[string]*Confusion, key string, expected, detected bool) {
	if groups[key] == nil {
		groups[key] = &Confusion{}
	}
	groups[key].Add(expected, detected)
}

// CorpusResult holds the outcomes of one corpus. Corpora are never pooled:
// their labels have their own semantics and are not comparable.
type CorpusResult struct {
	Name      string
	Detectors map[string]*tally
}

// Result is the raw outcome of Run, before report formatting.
type Result struct {
	Status       Status
	AbortReason  string
	Cases        int
	CasesErrored int
	Requests     int
	Corpora      []*CorpusResult
	Failures     []RequestFailure
}

type runner struct {
	client *Client
	cfg    RunConfig
	result *Result
	// consecutive counts request errors in a row.
	consecutive int
}

// Run evaluates every case of every corpus against the service. A run that
// cannot continue (rejected credentials, unreachable service, cancellation)
// returns the partial result with StatusAborted.
func Run(ctx context.Context, client *Client, cfg RunConfig, corpora []*Corpus) (*Result, error) {
	if err := cfg.Validate(corpora); err != nil {
		return nil, err
	}
	r := &runner{client: client, cfg: cfg, result: &Result{Status: StatusComplete}}
	for _, corpus := range corpora {
		current := &CorpusResult{Name: corpus.Header.Name, Detectors: map[string]*tally{}}
		for _, detector := range corpus.Detectors() {
			current.Detectors[detector] = newTally()
		}
		r.result.Corpora = append(r.result.Corpora, current)
	}
	for index, corpus := range corpora {
		for _, item := range corpus.Cases {
			if reason := r.evaluate(ctx, r.result.Corpora[index], item); reason != "" {
				r.result.Status, r.result.AbortReason = StatusAborted, reason
				return r.result, nil
			}
		}
	}
	if len(r.result.Failures) > 0 {
		r.result.Status = StatusCompleteWithErrors
	}
	return r.result, nil
}

// evaluate runs one case. It returns a non-empty reason to abort the run.
func (r *runner) evaluate(ctx context.Context, corpus *CorpusResult, item Case) string {
	r.result.Cases++
	errorsBefore := len(r.result.Failures)
	detectors := sortedKeys(item.Labels)

	var reason string
	switch r.cfg.Mode {
	case ModeAnnotate:
		reason = r.annotate(ctx, corpus, item, detectors)
	default:
		for _, detector := range detectors {
			if reason = r.enforce(ctx, corpus, item, detector); reason != "" {
				break
			}
		}
	}
	if len(r.result.Failures) > errorsBefore {
		r.result.CasesErrored++
	}
	return reason
}

func (r *runner) annotate(ctx context.Context, corpus *CorpusResult, item Case, detectors []string) string {
	r.result.Requests++
	result, err := r.client.Policy(ctx, r.cfg.Policy, item.InputType, item.Text)
	if err != nil {
		return r.fail(ctx, corpus, item, "", detectors, err)
	}
	r.consecutive = 0
	found := map[string]bool{}
	for _, detector := range result.Detectors {
		found[detector] = true
	}
	for _, detector := range detectors {
		corpus.Detectors[detector].observe(item, item.Labels[detector], found[detector])
	}
	return ""
}

func (r *runner) enforce(ctx context.Context, corpus *CorpusResult, item Case, detector string) string {
	route, _ := ScanRouteFor(detector) // validated by RunConfig.Validate
	r.result.Requests++
	result, err := r.client.Scan(ctx, route, item.InputType, item.Text)
	if err != nil {
		return r.fail(ctx, corpus, item, detector, []string{detector}, err)
	}
	r.consecutive = 0
	corpus.Detectors[detector].observe(item, item.Labels[detector], result.Decision != DecisionNone)
	return ""
}

// fail records a failed request and decides whether the run can go on.
func (r *runner) fail(ctx context.Context, corpus *CorpusResult, item Case, detector string, affected []string, err error) string {
	if ctx.Err() != nil {
		return "interrupted: " + ctx.Err().Error()
	}
	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		return "internal error: " + err.Error()
	}
	r.result.Failures = append(r.result.Failures, RequestFailure{
		Corpus: corpus.Name, CaseID: item.ID, Detector: detector,
		Kind: reqErr.Kind, Status: reqErr.Status, Message: reqErr.Message,
	})
	for _, name := range affected {
		corpus.Detectors[name].errored++
	}
	if reqErr.Kind == KindHTTPStatus && (reqErr.Status == http.StatusUnauthorized || reqErr.Status == http.StatusForbidden) {
		return fmt.Sprintf("service rejected the credentials (HTTP %d)", reqErr.Status)
	}
	if reqErr.Kind == KindLimitExceeded {
		return ""
	}
	r.consecutive++
	if r.cfg.MaxConsecutiveErrors > 0 && r.consecutive >= r.cfg.MaxConsecutiveErrors {
		return fmt.Sprintf("%d consecutive request errors", r.consecutive)
	}
	return ""
}
