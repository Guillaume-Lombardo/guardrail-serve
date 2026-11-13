package resources

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPatternsUsesOverrideFileWhenPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "detect_secret_contextual_patterns.yaml")
	content := []byte("patterns:\n  - name: custom\n    regex: '(?i)test(?P<secret>secret)'\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write override: %v", err)
	}

	patterns, err := LoadPatterns(dir, "detect_secret_contextual_patterns.yaml")
	if err != nil {
		t.Fatalf("load patterns: %v", err)
	}

	if len(patterns) != 1 {
		t.Fatalf("len(patterns) = %d, want 1", len(patterns))
	}
	if got, want := patterns[0].Name, "custom"; got != want {
		t.Fatalf("patterns[0].Name = %q, want %q", got, want)
	}
}

func TestLoadPatternsFallsBackToEmbeddedDefaultsWhenOverrideMissing(t *testing.T) {
	patterns, err := LoadPatterns(t.TempDir(), "detect_pii_patterns.yaml")
	if err != nil {
		t.Fatalf("load patterns: %v", err)
	}

	if len(patterns) == 0 {
		t.Fatal("patterns is empty, want embedded defaults")
	}
}

func TestLoadPoliciesReportsSource(t *testing.T) {
	content, source, err := LoadPolicies("")
	if err != nil || len(content) == 0 || source != "embedded defaults/policies.yaml" {
		t.Fatalf("embedded: source=%q len=%d err=%v", source, len(content), err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, PolicyFileName)
	if err := os.WriteFile(path, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if content, source, err = LoadPolicies(dir); err != nil || source != path || string(content) != "version: 1\n" {
		t.Fatalf("override: source=%q content=%q err=%v", source, content, err)
	}
}

func TestSecretOverrideSelection(t *testing.T) {
	dir := t.TempDir()
	for _, path := range []string{"", dir} {
		p, err := LoadSecretPatterns(path)
		if err != nil || p != nil {
			t.Fatal("missing override must select native")
		}
	}
	path := filepath.Join(dir, "detect_secret_contextual_patterns.yaml")
	for _, content := range []string{"patterns: []\n", "patterns: null\n", ""} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		p, err := LoadSecretPatterns(dir)
		if err != nil || p == nil || len(p) != 0 {
			t.Fatal("explicit empty override must replace native")
		}
	}
	if err := os.WriteFile(path, []byte("patterns: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSecretPatterns(dir); err == nil {
		t.Fatal("invalid override accepted")
	}
}
