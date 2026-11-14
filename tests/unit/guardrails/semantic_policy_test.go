package guardrails_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/guardrails"
	"github.com/g1lom/guardrail-serve/internal/semantic"
)

type policyClassifierFunc func(context.Context, []string) (semantic.PromptInjectionAssessment, error)

func (f policyClassifierFunc) DetectPromptInjection(ctx context.Context, texts []string) (semantic.PromptInjectionAssessment, error) {
	return f(ctx, texts)
}

func TestSemanticPolicyCancellationAndSafeFinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d, err := guardrails.NewSemanticPolicyDetector(policyClassifierFunc(func(_ context.Context, texts []string) (semantic.PromptInjectionAssessment, error) {
		if len(texts) != 1 || texts[0] != "é🙂" {
			t.Fatal("not per-text")
		}
		cancel()
		return semantic.PromptInjectionAssessment{Triggered: true, Score: 1}, nil
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Detect(ctx, "é🙂"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	for _, triggered := range []bool{false, true} {
		var logs bytes.Buffer
		d, _ = guardrails.NewSemanticPolicyDetector(policyClassifierFunc(func(_ context.Context, _ []string) (semantic.PromptInjectionAssessment, error) {
			return semantic.PromptInjectionAssessment{Triggered: triggered, Score: 0.95, Reason: "private", Model: "private", Metadata: map[string]any{"private": "private"}}, nil
		}), slog.New(slog.NewJSONHandler(&logs, nil)))
		if !d.Supports(domain.StageInput) || !d.Supports(domain.StageOutput) || d.Supports("other") {
			t.Fatal("stage contract")
		}
		findings, err := d.Detect(context.Background(), "é🙂")
		if err != nil {
			t.Fatal(err)
		}
		if !triggered && len(findings) != 0 {
			t.Fatal(findings)
		}
		if triggered && (len(findings) != 1 || findings[0].End != len("é🙂") || findings[0].Start != 0 || findings[0].Rule != "semantic_classification" || *findings[0].Score != 0.95) {
			t.Fatal(findings)
		}
		if logs.Len() != 0 {
			t.Fatal("unexpected log")
		}
	}
}

func TestSemanticPolicyRuleAllowlist(t *testing.T) {
	for value, want := range map[any]string{
		semantic.RuleSystemOneJudge: "systemone_judge",
		"attacker-chosen-rule":      "semantic_classification",
		42:                          "semantic_classification",
		nil:                         "semantic_classification",
	} {
		d, _ := guardrails.NewSemanticPolicyDetector(policyClassifierFunc(func(context.Context, []string) (semantic.PromptInjectionAssessment, error) {
			return semantic.PromptInjectionAssessment{Triggered: true, Score: 0.8, Metadata: map[string]any{semantic.MetadataRule: value}}, nil
		}), nil)
		findings, err := d.Detect(context.Background(), "text")
		if err != nil || len(findings) != 1 || findings[0].Rule != want {
			t.Fatalf("%v: %+v %v", value, findings, err)
		}
	}
}
