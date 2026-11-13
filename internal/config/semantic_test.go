package config

import (
	"strings"
	"testing"
)

func TestSemanticEnvironment(t *testing.T) {
	for _, key := range []string{"SEMANTIC_ENABLED", "SEMANTIC_URL", "SEMANTIC_FORMAT", "SEMANTIC_TIMEOUT", "SEMANTIC_THRESHOLD", "SEMANTIC_FAILURE_MODE", "SEMANTIC_MALICIOUS_LABELS"} {
		t.Setenv(key, "")
	}
	if c, err := Load().Semantic.NewClassifier(); err != nil || c != nil {
		t.Fatalf("default: %v %v", c, err)
	}
	for _, tc := range []struct{ key, value string }{
		{"SEMANTIC_ENABLED", "perhaps"}, {"SEMANTIC_ENABLED", "true"},
		{"SEMANTIC_URL", "file:///bad"}, {"SEMANTIC_URL", "https://user:secret@host"},
		{"SEMANTIC_FORMAT", "invalid"}, {"SEMANTIC_TIMEOUT", "0s"}, {"SEMANTIC_TIMEOUT", "bad"},
		{"SEMANTIC_THRESHOLD", "NaN"}, {"SEMANTIC_THRESHOLD", "0"}, {"SEMANTIC_THRESHOLD", "1.1"}, {"SEMANTIC_THRESHOLD", "bad"},
		{"SEMANTIC_FAILURE_MODE", "maybe"}, {"SEMANTIC_MALICIOUS_LABELS", "MALICIOUS,"},
	} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			_, err := Load().Semantic.NewClassifier()
			if err == nil {
				t.Fatal("accepted invalid setting")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("unsafe error")
			}
		})
	}
	t.Setenv("SEMANTIC_ENABLED", "true")
	t.Setenv("SEMANTIC_URL", "http://127.0.0.1:1/predict")
	t.Setenv("SEMANTIC_FORMAT", "tei_predict")
	t.Setenv("SEMANTIC_MALICIOUS_LABELS", "ATTACK,JAILBREAK")
	if _, err := Load().Semantic.NewClassifier(); err != nil {
		t.Fatal(err)
	} // no network
}
