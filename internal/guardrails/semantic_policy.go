package guardrails

import (
	"context"
	"errors"
	"log/slog"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/semantic"
)

// SemanticPolicyDetector adapts aggregated classification to a per-text policy
// detector. It supports both stages and reports the whole original text, never
// fragment offsets. Provider metadata and reasons never enter findings.
type SemanticPolicyDetector struct {
	classifier semantic.PromptInjectionDetector
	logger     *slog.Logger
}

var _ domain.Detector = (*SemanticPolicyDetector)(nil)

func NewSemanticPolicyDetector(classifier semantic.PromptInjectionDetector, logger *slog.Logger) (*SemanticPolicyDetector, error) {
	if classifier == nil {
		return nil, errors.New("semantic classifier is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SemanticPolicyDetector{classifier: classifier, logger: logger}, nil
}

func (*SemanticPolicyDetector) Name() string { return "semantic_prompt_injection" }
func (*SemanticPolicyDetector) Supports(stage domain.Stage) bool {
	return stage == domain.StageInput || stage == domain.StageOutput
}
func (*SemanticPolicyDetector) BlockReason() string { return "Potential prompt injection detected." }
func (d *SemanticPolicyDetector) Detect(ctx context.Context, text string) ([]domain.Detection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a, err := d.classifier.DetectPromptInjection(ctx, []string{text})
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, err
	}
	if degraded, _ := a.Metadata["classifier_degraded"].(bool); degraded {
		// Deliberately fixed fields: provider metadata cannot create log cardinality
		// or leak a response body, URL, label, model name or input value.
		d.logger.WarnContext(ctx, "semantic classifier degraded", "detector", d.Name(), "failure_mode", "open")
		return nil, nil
	}
	if !a.Triggered || text == "" {
		return nil, nil
	}
	score := a.Score
	return []domain.Detection{{Rule: "semantic_classification", Type: "PROMPT_INJECTION", Start: 0, End: len(text), Score: &score}}, nil
}
