package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/g1lom/guardrail-serve/internal/domain"
)

// SchemaVersion is the only accepted policy file version.
const SchemaVersion = 1

type fileSchema struct {
	Version  int            `yaml:"version"`
	Policies []policySchema `yaml:"policies"`
}

type policySchema struct {
	Name        string                   `yaml:"name"`
	Description string                   `yaml:"description"`
	Mode        string                   `yaml:"mode"`
	Stages      map[string]*[]stepSchema `yaml:"stages"`
}

type stepSchema struct {
	Detector string  `yaml:"detector"`
	Action   string  `yaml:"action"`
	Mask     *string `yaml:"mask"`
}

// Parse decodes and validates a policy file. Unknown fields, unknown names,
// duplicates and incomplete definitions are errors; nothing falls back to a
// default policy. detectors maps the detector names a policy may reference.
// defaultMask is used by mask steps that declare no mask.
func Parse(content []byte, source string, detectors map[string]domain.Detector, defaultMask Mask) (*Catalog, error) {
	catalog, err := parse(content, detectors, defaultMask)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return catalog, nil
}

func parse(content []byte, detectors map[string]domain.Detector, defaultMask Mask) (*Catalog, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	var file fileSchema
	if err := decoder.Decode(&file); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("policy file is empty")
		}
		return nil, fmt.Errorf("decode: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("policy file must contain exactly one YAML document")
	}
	if file.Version != SchemaVersion {
		return nil, fmt.Errorf("unsupported version %d (expected %d)", file.Version, SchemaVersion)
	}
	if len(file.Policies) == 0 {
		return nil, errors.New("at least one policy is required")
	}
	policies := make([]*Policy, 0, len(file.Policies))
	seen := map[string]int{}
	for index, item := range file.Policies {
		if previous, duplicate := seen[item.Name]; duplicate {
			return nil, fmt.Errorf("policy %d: duplicate name %q (already defined by policy %d)", index, item.Name, previous)
		}
		seen[item.Name] = index
		policy, err := compilePolicy(item, detectors, defaultMask)
		if err != nil {
			return nil, fmt.Errorf("policy %d (%q): %w", index, item.Name, err)
		}
		policies = append(policies, policy)
	}
	return NewCatalog(policies...)
}

func compilePolicy(item policySchema, detectors map[string]domain.Detector, defaultMask Mask) (*Policy, error) {
	if !ValidName(item.Name) {
		return nil, fmt.Errorf("name must match %s", namePattern)
	}
	if item.Mode == "" {
		return nil, errors.New("mode is required (enforce or detect)")
	}
	mode, err := domain.ParseMode(item.Mode)
	if err != nil {
		return nil, err
	}
	for _, key := range sortedKeys(item.Stages) {
		if _, err := domain.ParseStage(key); err != nil {
			return nil, err
		}
	}
	chains := map[domain.Stage][]Step{}
	for _, stage := range domain.Stages() {
		declared, ok := item.Stages[string(stage)]
		if !ok || declared == nil {
			return nil, fmt.Errorf("stage %s must be declared as a list (use [] to apply only payload limits)", stage)
		}
		steps := make([]Step, 0, len(*declared))
		for index, raw := range *declared {
			step, err := compileStep(raw, detectors, defaultMask)
			if err != nil {
				return nil, fmt.Errorf("stage %s step %d: %w", stage, index, err)
			}
			steps = append(steps, step)
		}
		chains[stage] = steps
	}
	return NewPolicy(item.Name, mode, chains[domain.StageInput], chains[domain.StageOutput])
}

func compileStep(raw stepSchema, detectors map[string]domain.Detector, defaultMask Mask) (Step, error) {
	detector, ok := detectors[raw.Detector]
	if !ok {
		return Step{}, fmt.Errorf("unknown detector %q (expected one of %s)", raw.Detector, strings.Join(sortedKeys(detectors), ", "))
	}
	if raw.Action == "" {
		return Step{}, errors.New("action is required (block, mask or annotate)")
	}
	action, err := domain.ParseAction(raw.Action)
	if err != nil {
		return Step{}, err
	}
	step := Step{Detector: detector, Action: action}
	if raw.Mask != nil && action != domain.ActionMask {
		return Step{}, fmt.Errorf("mask is only allowed with action mask, not %s", action)
	}
	if action == domain.ActionMask {
		step.Mask = defaultMask
		if raw.Mask != nil {
			if step.Mask, err = ParseMaskTemplate(*raw.Mask); err != nil {
				return Step{}, err
			}
		}
	}
	return step, nil
}

func sortedKeys[V any](items map[string]V) []string {
	keys := make([]string, 0, len(items))
	for key := range items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
