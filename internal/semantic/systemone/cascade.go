package systemone

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/g1lom/guardrail-serve/internal/semantic"
)

var _ semantic.PromptInjectionDetector = (*Cascade)(nil)

// Cascade scores texts with the primary classifier and asks the judge only
// when the primary score lies in the zone. It is safe for concurrent use.
type Cascade struct {
	primary  semantic.PromptInjectionDetector
	judge    semantic.PromptInjectionDetector
	zone     Zone
	observer Observer
}

// NewCascade validates the zone. observer may be nil.
func NewCascade(primary, judge semantic.PromptInjectionDetector, zone Zone, observer Observer) (*Cascade, error) {
	if primary == nil || judge == nil {
		return nil, errors.New("systemone cascade: primary classifier and judge are required")
	}
	if err := zone.Validate(); err != nil {
		return nil, fmt.Errorf("systemone cascade: %w", err)
	}
	return &Cascade{primary: primary, judge: judge, zone: zone, observer: observer}, nil
}

// DetectPromptInjection returns the primary assessment outside the zone and
// the judge assessment inside it. A failed or degraded primary assessment is
// returned unchanged: it is never read as a score and never escalated.
func (c *Cascade) DetectPromptInjection(ctx context.Context, texts []string) (semantic.PromptInjectionAssessment, error) {
	if !anyContent(texts) {
		c.route(RouteEmpty)
		return c.primary.DetectPromptInjection(ctx, texts)
	}
	assessment, err := c.primary.DetectPromptInjection(ctx, texts)
	if err != nil {
		c.route(RoutePrimaryFailure)
		return semantic.PromptInjectionAssessment{}, err
	}
	if degraded, _ := assessment.Metadata[semantic.MetadataDegraded].(bool); degraded {
		c.route(RoutePrimaryFailure)
		return assessment, nil
	}
	if err := ctx.Err(); err != nil {
		return semantic.PromptInjectionAssessment{}, err
	}
	if score := assessment.Score; math.IsNaN(score) || score < 0 || score > 1 {
		c.route(RoutePrimaryFailure)
		return semantic.PromptInjectionAssessment{}, errors.New("systemone cascade: invalid primary score")
	}
	switch {
	case assessment.Score < c.zone.Lower:
		c.route(RouteBelowZone)
		return assessment, nil
	case assessment.Score > c.zone.Upper:
		c.route(RouteAboveZone)
		return assessment, nil
	}
	c.route(RouteJudged)
	return c.judge.DetectPromptInjection(ctx, texts)
}

func (c *Cascade) route(route Route) {
	if c.observer != nil {
		c.observer.ObserveRoute(route)
	}
}

func anyContent(texts []string) bool {
	for _, text := range texts {
		if strings.TrimSpace(text) != "" {
			return true
		}
	}
	return false
}
