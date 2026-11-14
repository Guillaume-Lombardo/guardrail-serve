package semantic

import "context"

// Assessment metadata keys shared by implementations and the policy adapter.
// Values are fixed enumerations, never text or provider content.
const (
	// MetadataDegraded is true when a fail-open implementation could not score.
	MetadataDegraded = "classifier_degraded"
	// MetadataRule names the component that decided, among the Rule* values.
	MetadataRule = "semantic_rule"
)

// Finding rules reported by the semantic policy adapter.
const (
	RuleClassification = "semantic_classification"
	RuleSystemOneJudge = "systemone_judge"
)

type PromptInjectionAssessment struct {
	Triggered bool
	Score     float64
	Reason    string
	Model     string
	Metadata  map[string]any
}

type PromptInjectionDetector interface {
	DetectPromptInjection(context.Context, []string) (PromptInjectionAssessment, error)
}
