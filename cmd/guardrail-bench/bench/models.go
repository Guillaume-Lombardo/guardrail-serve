// Package bench runs the semantic model benchmark (ADR 0023): it drives the real
// guardrail-serve handler in-process on loopback, records upstream scores and
// judge answers through caching proxies, freezes a calibration protocol before
// the test split, and computes the reported metrics from per-case records.
package bench

import (
	"fmt"
	"sort"
)

// Kind tells how a model's score is produced.
type Kind string

const (
	// KindClassifier returns a probability: the threshold is calibrated (R1).
	KindClassifier Kind = "classifier"
	// KindGenerative returns a strictly parsed label mapped to 1 or 0: no free parameter.
	KindGenerative Kind = "generative"
)

// Model is one pinned local candidate served by a sidecar image.
type Model struct {
	Name              string `json:"name"`
	ID                string `json:"id"`
	Revision          string `json:"revision"`
	SafetensorsSHA256 string `json:"safetensors_sha256"`
	MaliciousLabels   string `json:"malicious_labels"`
	License           string `json:"license"`
	Kind              Kind   `json:"kind"`
	Gated             bool   `json:"gated"`
}

// ReadyLabel is what the sidecar reports on /readyz for this model.
func (m Model) ReadyLabel() string { return m.ID + "@" + m.Revision[:12] }

// Models lists the local candidates. Revisions are the `main` commits read on
// 14/11/2026; weights hashes are the LFS sha256 of model.safetensors, verified
// again by every image build.
var Models = []Model{
	{Name: "pg2-86m", ID: "meta-llama/Llama-Prompt-Guard-2-86M", Revision: "a8ded8e697ce7c355e395a0df51f94adb4a2fd27",
		SafetensorsSHA256: "e72017dbbe89c1232dcbc4a74ce0c389db5b468c42afd05850347b2a8c5f6b09", MaliciousLabels: "LABEL_1",
		License: "Llama 4 Community License", Kind: KindClassifier, Gated: true},
	{Name: "pg2-22m", ID: "meta-llama/Llama-Prompt-Guard-2-22M", Revision: "11614a155199674a0a95e6602d6ab0417b790ed0",
		SafetensorsSHA256: "5120e30bcd536ce285345d9ec104bea6bd6e8f94365b99a340c764f417ea5fa1", MaliciousLabels: "LABEL_1",
		License: "Llama 4 Community License", Kind: KindClassifier, Gated: true},
	{Name: "deberta-v2", ID: "protectai/deberta-v3-base-prompt-injection-v2", Revision: "90c9989b1a342275dd0d1a95aad283c04e075671",
		SafetensorsSHA256: "6521cb8d0ac08148c81464899c424e6148fcc62befa371089fa4061d8b6e0424", MaliciousLabels: "INJECTION",
		License: "Apache-2.0", Kind: KindClassifier},
	{Name: "sentinel", ID: "qualifire/prompt-injection-sentinel", Revision: "e24131782819a4787c129ed2b9a4a67ae57a584e",
		SafetensorsSHA256: "fcba2fec67d9d2c5bd6e387f559255efd4f8b903ecaa2e97bdb9b46831f04239", MaliciousLabels: "jailbreak",
		License: "Elastic License 2.0", Kind: KindClassifier, Gated: true},
	{Name: "qwen3guard-0.6b", ID: "Qwen/Qwen3Guard-Gen-0.6B", Revision: "fada3b2f655b89601929198343c94cd2f64d93cc",
		SafetensorsSHA256: "4f3ce47ebd968cddb67de08d8764f8ede7c410a7d1fb9e08145a4c7a2f2e5c0f", MaliciousLabels: "Jailbreak",
		License: "Apache-2.0", Kind: KindGenerative},
}

// CascadePrimary is the classifier used as the cascade's primary.
const CascadePrimary = "pg2-86m"

// DefaultThreshold is the production SEMANTIC_THRESHOLD, reported as "current".
const DefaultThreshold = 0.9

// LookupModel returns the registered model with that name.
func LookupModel(name string) (Model, error) {
	for _, model := range Models {
		if model.Name == name {
			return model, nil
		}
	}
	names := make([]string, 0, len(Models))
	for _, model := range Models {
		names = append(names, model.Name)
	}
	sort.Strings(names)
	return Model{}, fmt.Errorf("unknown model %q (known: %v)", name, names)
}
