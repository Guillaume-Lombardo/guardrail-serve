package systemone

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/g1lom/guardrail-serve/internal/semantic"
	"github.com/g1lom/guardrail-serve/internal/semantic/httpclassifier"
)

// Masker returns a copy of text where sensitive values are replaced. The
// judge sends nothing when it fails.
type Masker interface {
	Mask(ctx context.Context, text string) (string, error)
}

// Judgment describes one attempted judgment of one text, without any value.
type Judgment struct {
	Outcome     Outcome
	Duration    time.Duration
	InputTokens int64
}

// Route records which component decided one cascade evaluation.
type Route string

const (
	RouteJudged         Route = "judged"
	RouteBelowZone      Route = "below_zone"
	RouteAboveZone      Route = "above_zone"
	RoutePrimaryFailure Route = "primary_failure"
	RouteEmpty          Route = "empty"
)

// Routes lists every Route, for label allowlists.
func Routes() []Route {
	return []Route{RouteJudged, RouteBelowZone, RouteAboveZone, RoutePrimaryFailure, RouteEmpty}
}

// Observer receives value-free observations. It must be concurrency safe,
// return promptly and never panic.
type Observer interface {
	ObserveJudgment(Judgment)
	ObserveRoute(Route)
}

const (
	reasonTriggered = "Potential prompt injection detected by the System One judge."
	reasonDegraded  = "System One judge unavailable; failing open."
)

var _ semantic.PromptInjectionDetector = (*Judge)(nil)

// Judge asks the fixed prompt-injection question about each masked text. It
// is safe for concurrent use.
type Judge struct {
	cfg      settings
	client   *client
	masker   Masker
	observer Observer
}

// NewJudge validates cfg and performs no network call. masker is mandatory;
// observer may be nil.
func NewJudge(cfg Config, masker Masker, observer Observer) (*Judge, error) {
	if masker == nil {
		return nil, errors.New("systemone judge: a masker is required")
	}
	resolved, err := cfg.resolve()
	if err != nil {
		return nil, fmt.Errorf("systemone judge config: %w", err)
	}
	return &Judge{
		cfg: resolved,
		client: &client{
			endpoint: resolved.endpoint, model: resolved.model, key: resolved.key,
			question: resolved.question, maxResponse: resolved.maxResponse, http: newHTTPClient(),
		},
		masker:   masker,
		observer: observer,
	}, nil
}

// DetectPromptInjection judges every non-blank text separately and reports
// the maximum injection probability. Blank texts are never sent.
func (j *Judge) DetectPromptInjection(ctx context.Context, texts []string) (semantic.PromptInjectionAssessment, error) {
	top := 0.0
	for _, text := range texts {
		if strings.TrimSpace(text) == "" {
			continue
		}
		probability, failure := j.judge(ctx, text)
		if failure != nil {
			return j.fail(failure)
		}
		top = max(top, probability)
	}
	if err := ctx.Err(); err != nil {
		return j.fail(&Error{Kind: FailureCanceled, cause: err})
	}
	assessment := semantic.PromptInjectionAssessment{
		Triggered: top >= j.cfg.threshold,
		Score:     top,
		Model:     j.cfg.model,
		Metadata: map[string]any{
			semantic.MetadataRule: semantic.RuleSystemOneJudge,
			"systemone_question":  string(j.cfg.question),
			"systemone_threshold": j.cfg.threshold,
		},
	}
	if assessment.Triggered {
		assessment.Reason = reasonTriggered
	}
	return assessment, nil
}

// judge masks then asks. A masking failure or an oversized masked text
// returns before any request is built.
func (j *Judge) judge(ctx context.Context, text string) (probability float64, failure *Error) {
	started := time.Now()
	var tokens int64
	defer func() {
		outcome := OutcomeSuccess
		if failure != nil {
			outcome = failure.Kind
		}
		if j.observer != nil {
			j.observer.ObserveJudgment(Judgment{Outcome: outcome, Duration: time.Since(started), InputTokens: tokens})
		}
	}()
	if err := ctx.Err(); err != nil {
		return 0, &Error{Kind: FailureCanceled, cause: err}
	}
	masked, err := j.masker.Mask(ctx, text)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, &Error{Kind: FailureCanceled, cause: ctxErr}
	}
	if err != nil {
		return 0, newError(FailureMasking)
	}
	if utf8.RuneCountInString(masked) > j.cfg.maxRunes {
		return 0, newError(FailureTextTooLarge)
	}
	callCtx, cancel := context.WithTimeout(ctx, j.cfg.timeout)
	defer cancel()
	result, err := j.client.ask(callCtx, masked)
	if err != nil {
		return 0, toFailure(ctx, callCtx, err)
	}
	tokens = result.inputTokens
	return result.probability, nil
}

// fail applies the failure mode to provider failures only. Cancellation is
// always an error (nobody is waiting), and so are failures the input itself
// provokes (masking, size, a provider rejection): fail-open is for an unavailable
// provider, it must not let a caller turn the judge off with crafted text.
func (j *Judge) fail(failure *Error) (semantic.PromptInjectionAssessment, error) {
	switch failure.Kind {
	case FailureCanceled, FailureMasking, FailureTextTooLarge, FailureRejected:
		return semantic.PromptInjectionAssessment{}, failure
	}
	if j.cfg.failureMode == httpclassifier.FailClosed {
		return semantic.PromptInjectionAssessment{}, failure
	}
	return semantic.PromptInjectionAssessment{
		Reason: reasonDegraded,
		Model:  j.cfg.model,
		Metadata: map[string]any{
			semantic.MetadataDegraded: true,
			"classifier_failure":      string(failure.Kind),
		},
	}, nil
}
