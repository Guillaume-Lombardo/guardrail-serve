package semantic

import "context"

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
