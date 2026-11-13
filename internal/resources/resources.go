package resources

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/g1lom/guardrail-serve/internal/guardrails"
)

//go:embed defaults/*.yaml
var defaultsFS embed.FS

type patternsFile struct {
	Patterns []guardrails.NamedPattern `yaml:"patterns"`
}

func LoadPatterns(overrideDir, name string) ([]guardrails.NamedPattern, error) {
	content, err := loadContent(overrideDir, name)
	if err != nil {
		return nil, err
	}

	var file patternsFile
	if err := yaml.Unmarshal(content, &file); err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}

	return file.Patterns, nil
}

// LoadSecretPatterns returns nil for the native scanner, or a non-nil list
// replacing it when an explicit legacy YAML override exists (even if empty).
func LoadSecretPatterns(overrideDir string) ([]guardrails.NamedPattern, error) {
	if overrideDir == "" {
		return nil, nil
	}
	path := filepath.Join(overrideDir, "detect_secret_contextual_patterns.yaml")
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read secret override: %w", err)
	}
	var file patternsFile
	if err := yaml.Unmarshal(content, &file); err != nil {
		return nil, fmt.Errorf("decode secret override: %w", err)
	}
	return append([]guardrails.NamedPattern{}, file.Patterns...), nil
}

// PolicyFileName is the policy catalog file, embedded or overridden as a whole.
const PolicyFileName = "policies.yaml"

// LoadPolicies returns the policy file content and a source label for errors.
// An override file replaces the embedded catalog entirely; nothing is merged.
func LoadPolicies(overrideDir string) ([]byte, string, error) {
	return loadSource(overrideDir, PolicyFileName)
}

func loadContent(overrideDir, name string) ([]byte, error) {
	content, _, err := loadSource(overrideDir, name)
	return content, err
}

func loadSource(overrideDir, name string) ([]byte, string, error) {
	if overrideDir != "" {
		path := filepath.Join(overrideDir, name)
		if content, err := os.ReadFile(path); err == nil {
			return content, path, nil
		} else if !os.IsNotExist(err) {
			return nil, "", fmt.Errorf("read override %s: %w", path, err)
		}
	}

	embedded := filepath.ToSlash(filepath.Join("defaults", name))
	content, err := defaultsFS.ReadFile(embedded)
	if err != nil {
		return nil, "", fmt.Errorf("read embedded %s: %w", name, err)
	}
	return content, "embedded " + embedded, nil
}
