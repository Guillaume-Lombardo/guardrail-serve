package bench

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
	"github.com/g1lom/guardrail-serve/tests/eval/semanticbenchfixtures"
)

// Corpus names accepted by the bench. Each is reported on its own: labels of
// different corpora are never pooled.
const (
	CorpusCalibration = "bench-calibration"
	CorpusTest        = "bench-test"
	CorpusFrench      = "french-injection-v1"
	CorpusOriginal    = "original-v1"
)

// Detector is the only labelled detector the bench measures.
const Detector = semanticbenchfixtures.Detector

// Case is one labelled text.
type Case struct {
	ID        string
	Lang      string
	InputType string
	Text      string
	Label     bool
}

// LoadedCorpus is a validated corpus and the sha256 of the exact file bytes.
type LoadedCorpus struct {
	Name   string
	SHA256 string
	Cases  []Case
}

// CorpusNames lists the accepted corpus names.
func CorpusNames() []string {
	return []string{CorpusCalibration, CorpusTest, CorpusFrench, CorpusOriginal}
}

// LoadCorpus loads one corpus from the repository root. The benchmark splits go
// through semanticbenchfixtures.Load and Validate, which check every file hash
// against the manifest before anything is measured.
func LoadCorpus(root, name string) (*LoadedCorpus, error) {
	var parsed *eval.Corpus
	switch name {
	case CorpusCalibration, CorpusTest:
		bundle, err := semanticbenchfixtures.Load(filepath.Join(root, semanticbenchfixtures.Dir))
		if err != nil {
			return nil, err
		}
		if err := bundle.Validate(); err != nil {
			return nil, fmt.Errorf("semantic bench corpus is not valid: %w", err)
		}
		split := semanticbenchfixtures.Calibration
		if name == CorpusTest {
			split = semanticbenchfixtures.Test
		}
		parsed = bundle.Corpora[split]
	case CorpusFrench:
		corpus, err := eval.LoadCorpus(filepath.Join(root, "tests/eval/corpus/guardrail-serve-french-injection-v1.jsonl"))
		if err != nil {
			return nil, err
		}
		parsed = corpus
	case CorpusOriginal:
		corpus, err := eval.LoadCorpus(filepath.Join(root, "tests/eval/corpus/guardrail-serve-original-v1.jsonl"))
		if err != nil {
			return nil, err
		}
		parsed = corpus
	default:
		return nil, fmt.Errorf("unknown corpus %q (known: %v)", name, CorpusNames())
	}
	loaded := &LoadedCorpus{Name: name, SHA256: parsed.SHA256}
	for _, item := range parsed.Cases {
		label, ok := item.Labels[Detector]
		if !ok {
			return nil, fmt.Errorf("corpus %s: case %s has no %s label", name, item.ID, Detector)
		}
		inputType := string(item.InputType)
		if inputType == "" {
			inputType = "request"
		}
		loaded.Cases = append(loaded.Cases, Case{ID: item.ID, Lang: item.Lang, InputType: inputType, Text: item.Text, Label: label})
	}
	if len(loaded.Cases) == 0 {
		return nil, errors.New("corpus " + name + " has no case")
	}
	sort.SliceStable(loaded.Cases, func(i, j int) bool { return loaded.Cases[i].ID < loaded.Cases[j].ID })
	return loaded, nil
}
