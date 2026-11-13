package loaders_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
	"github.com/g1lom/guardrail-serve/tests/eval/loaders"
)

func runImport(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := loaders.Main(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func scratch(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), loaders.ScratchDir, name)
}

func TestMainImportsEachDatasetFromLocalFiles(t *testing.T) {
	for name, tc := range map[string]struct {
		args  []string
		cases int
		lang  string
	}{
		"bipia":           {[]string{"--dataset", "bipia", "--input", "testdata/bipia_attack_sample.json"}, 3, "en"},
		"presidio":        {[]string{"--dataset", "presidio", "--input", "testdata/presidio_sample.json", "--lang", "fr", "--name", "presidio-sample"}, 3, "fr"},
		"agentdojo":       {[]string{"--dataset", "agentdojo", "--input", "testdata/agentdojo"}, 2, "en"},
		"agentdojo files": {[]string{"--dataset", "agentdojo", "--input", "testdata/agentdojo/slack/trace_important.json", "--input", "testdata/agentdojo/banking/trace_direct.json"}, 2, "en"},
	} {
		t.Run(name, func(t *testing.T) {
			output := scratch(t, "out.jsonl")
			code, stdout, stderr := runImport(t, append(tc.args, "--output", output)...)
			if code != loaders.ExitOK || stderr != "" || !strings.Contains(stdout, "do not commit it") {
				t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
			}
			corpus, err := eval.LoadCorpus(output)
			if err != nil || len(corpus.Cases) != tc.cases || corpus.Cases[0].Lang != tc.lang {
				t.Fatalf("corpus = %+v err = %v", corpus, err)
			}
			if corpus.Header.Source == nil || corpus.Header.Source.URL != "" {
				t.Fatalf("source = %+v", corpus.Header.Source)
			}
		})
	}
}

func TestMainRecordsDigestOfLocalFile(t *testing.T) {
	output := scratch(t, "bipia.jsonl")
	if code, _, stderr := runImport(t, "--dataset", "bipia", "--input", "testdata/bipia_attack_sample.json", "--revision", "abc1234", "--output", output); code != loaders.ExitOK {
		t.Fatal(stderr)
	}
	corpus, err := eval.LoadCorpus(output)
	if err != nil {
		t.Fatal(err)
	}
	want := loaders.SHA256Hex(fixture(t, "bipia_attack_sample.json"))
	if corpus.Header.Source.SHA256 != want || corpus.Header.Source.Revision != "abc1234" {
		t.Fatalf("source = %+v", corpus.Header.Source)
	}
}

func TestMainRefusesUnsafeOrInvalidInvocations(t *testing.T) {
	good := []string{"--dataset", "bipia", "--input", "testdata/bipia_attack_sample.json"}
	inside := scratch(t, "x.jsonl")
	outside := filepath.Join(t.TempDir(), "x.jsonl")
	const pinned = "https://raw.example.org/org/repo/0123456789abcdef0123456789abcdef01234567/a.json"
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"output outside scratch": {append(append([]string{}, good...), "--output", outside), loaders.ScratchDir},
		"no output":              {good, "--output is required"},
		"unknown dataset":        {[]string{"--dataset", "other", "--input", "x", "--output", inside}, "dataset must be"},
		"no source":              {[]string{"--dataset", "bipia", "--output", inside}, "either --input or --url"},
		"both sources":           {append(append([]string{}, good...), "--url", pinned, "--output", inside), "either --input or --url"},
		"url without digest":     {[]string{"--dataset", "bipia", "--url", pinned, "--revision", "0123456789abcdef0123456789abcdef01234567", "--output", inside}, "--sha256"},
		"plain http url":         {[]string{"--dataset", "bipia", "--url", "http://raw.example.org/a.json", "--sha256", strings.Repeat("a", 64), "--revision", "0123456", "--output", inside}, "https"},
		"digest with input":      {append(append([]string{}, good...), "--sha256", strings.Repeat("a", 64), "--output", inside), "--sha256 only applies"},
		"entities on wrong set":  {append(append([]string{}, good...), "--entities", "EMAIL_ADDRESS", "--output", inside), "--entities"},
		"negative limit":         {append(append([]string{}, good...), "--limit", "-1", "--output", inside), "--limit"},
		"two files for bipia":    {[]string{"--dataset", "bipia", "--input", "a", "--input", "b", "--output", inside}, "exactly one"},
		"stray argument":         {append(append([]string{}, good...), "--output", inside, "stray"), "unexpected argument"},
		"unknown flag":           {append(append([]string{}, good...), "--nope"), "flag provided but not defined"},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runImport(t, tc.args...)
			wantCode := loaders.ExitUsage
			if name == "two files for bipia" {
				wantCode = loaders.ExitFailure
			}
			if code != wantCode || !strings.Contains(stderr, tc.want) {
				t.Fatalf("exit %d: %s", code, stderr)
			}
		})
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("a refused invocation must not write the output")
	}
}

func TestMainReportsUnusableInputs(t *testing.T) {
	notDataset := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(notDataset, []byte(`{"unexpected": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	output := scratch(t, "x.jsonl")
	for name, args := range map[string][]string{
		"wrong shape":     {"--dataset", "bipia", "--input", notDataset},
		"missing file":    {"--dataset", "presidio", "--input", filepath.Join(t.TempDir(), "none.json")},
		"not a trace":     {"--dataset", "agentdojo", "--input", notDataset},
		"empty directory": {"--dataset", "agentdojo", "--input", t.TempDir()},
	} {
		code, _, stderr := runImport(t, append(args, "--output", output)...)
		if code != loaders.ExitFailure || !strings.Contains(stderr, "eval-import: error:") {
			t.Errorf("%s: exit %d: %s", name, code, stderr)
		}
	}
	if _, err := os.Stat(output); err == nil {
		t.Fatal("no corpus must be written when the import fails")
	}
}

func TestMainAllowsExplicitOutputOutsideScratch(t *testing.T) {
	output := filepath.Join(t.TempDir(), "ignored-elsewhere.jsonl")
	code, _, stderr := runImport(t, "--dataset", "bipia", "--input", "testdata/bipia_attack_sample.json", "--output", output, "--allow-any-output")
	if code != loaders.ExitOK {
		t.Fatal(stderr)
	}
	if _, err := eval.LoadCorpus(output); err != nil {
		t.Fatal(err)
	}
}
