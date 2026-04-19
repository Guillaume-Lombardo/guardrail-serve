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

func loadContent(overrideDir, name string) ([]byte, error) {
	if overrideDir != "" {
		path := filepath.Join(overrideDir, name)
		if content, err := os.ReadFile(path); err == nil {
			return content, nil
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read override %s: %w", path, err)
		}
	}

	content, err := defaultsFS.ReadFile(filepath.ToSlash(filepath.Join("defaults", name)))
	if err != nil {
		return nil, fmt.Errorf("read embedded %s: %w", name, err)
	}
	return content, nil
}
