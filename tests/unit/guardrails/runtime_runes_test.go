package guardrails_test

import (
	"context"
	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/guardrails"
	"testing"
)

func TestMaxLengthCountsRunesAcrossTexts(t *testing.T) {
	for _, tc := range []struct {
		texts   []string
		blocked bool
	}{
		{[]string{"é", "界🙂"}, false},
		{[]string{"é界🙂x"}, true},
	} {
		result, err := guardrails.NewMaxLengthGuardrail(3, 3).Apply(context.Background(), domain.Payload{Texts: tc.texts})
		if err != nil {
			t.Fatal(err)
		}
		if (result.Decision == domain.DecisionBlocked) != tc.blocked {
			t.Fatalf("texts %q: decision %v", tc.texts, result.Decision)
		}
	}
}
