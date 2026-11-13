package eval_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

type cliResult struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, env map[string]string, args ...string) cliResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := eval.Main(context.Background(), args, func(key string) string { return env[key] }, &stdout, &stderr)
	return cliResult{code, stdout.String(), stderr.String()}
}

func cliFixture(t *testing.T) (*fakeService, string) {
	t.Helper()
	svc := newFakeService(t)
	svc.Findings = map[string][]string{"hit": {"detect_pii"}}
	svc.Scans = map[string]string{"/scan/pii|hit": "GUARDRAIL_INTERVENED"}
	return svc, corpusFile(t, "unit",
		caseLine("c-1", "en", "hit", `"detect_pii":true`),
		caseLine("c-2", "fr", "clean", `"detect_pii":false`))
}

func TestCLIRunSuccessJSONAndTextAndOutputFile(t *testing.T) {
	svc, corpus := cliFixture(t)

	res := runCLI(t, nil, "run", "--corpus", corpus, "--base-url", svc.Server.URL, "--format", "json")
	if res.code != eval.ExitOK || res.stderr != "" {
		t.Fatalf("code = %d stderr = %q", res.code, res.stderr)
	}
	var report eval.Report
	if err := json.Unmarshal([]byte(res.stdout), &report); err != nil || report.Corpora[0].Aggregate.Micro.Counts != (eval.Confusion{TP: 1, TN: 1}) {
		t.Fatalf("report = %+v err = %v", report.Corpora[0].Aggregate, err)
	}

	res = runCLI(t, nil, "run", "--corpus", corpus, "--base-url", svc.Server.URL)
	if res.code != eval.ExitOK || !strings.Contains(res.stdout, "guardrail-eval report v1") {
		t.Fatalf("text: %+v", res)
	}

	out := filepath.Join(t.TempDir(), "report.json")
	res = runCLI(t, nil, "run", "--corpus", corpus, "--base-url", svc.Server.URL, "--format", "json", "--output", out)
	data, err := os.ReadFile(out)
	if res.code != eval.ExitOK || res.stdout != "" || err != nil || !json.Valid(data) {
		t.Fatalf("output file: %+v %v", res, err)
	}
}

func TestCLIEnforceAndEnvironmentBaseURL(t *testing.T) {
	svc, corpus := cliFixture(t)
	env := map[string]string{eval.EnvBaseURL: svc.Server.URL}
	res := runCLI(t, env, "run", "--corpus", corpus, "--mode", "enforce", "--format", "json")
	if res.code != eval.ExitOK {
		t.Fatalf("%+v", res)
	}
	if got := svc.Seen()[0].Path; got != "/scan/pii" {
		t.Fatalf("path = %s", got)
	}
	// --policy is meaningless in enforce mode and rejected, not ignored.
	res = runCLI(t, env, "run", "--corpus", corpus, "--mode", "enforce", "--policy", "default")
	if res.code != eval.ExitUsage || !strings.Contains(res.stderr, "--policy") {
		t.Fatalf("%+v", res)
	}
}

func TestCLIUsageErrorsSendNothing(t *testing.T) {
	svc, corpus := cliFixture(t)
	other := corpusFile(t, "unit", caseLine("c-1", "en", "x", `"detect_pii":true`))
	bad := writeFile(t, "bad.jsonl", "not a corpus\n")
	base := []string{"--base-url", svc.Server.URL}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no command":        {nil, "Usage"},
		"unknown command":   {[]string{"explode"}, "unknown command"},
		"no corpus":         {append([]string{"run"}, base...), "--corpus is required"},
		"no base url":       {[]string{"run", "--corpus", corpus}, "--base-url"},
		"bad mode":          {append([]string{"run", "--corpus", corpus, "--mode", "dry"}, base...), "mode must be"},
		"bad format":        {append([]string{"run", "--corpus", corpus, "--format", "xml"}, base...), "format must be"},
		"bad auth scheme":   {append([]string{"run", "--corpus", corpus, "--auth-scheme", "basic"}, base...), "auth scheme"},
		"bad url":           {[]string{"run", "--corpus", corpus, "--base-url", "localhost"}, "absolute"},
		"missing corpus":    {append([]string{"run", "--corpus", filepath.Join(t.TempDir(), "none")}, base...), "open corpus"},
		"invalid corpus":    {append([]string{"run", "--corpus", bad}, base...), "line 1"},
		"duplicate corpora": {append([]string{"run", "--corpus", corpus, "--corpus", other}, base...), "used by both"},
		"bad policy":        {append([]string{"run", "--corpus", corpus, "--policy", "../x"}, base...), "policy"},
		"unknown flag":      {append([]string{"run", "--corpus", corpus, "--nope"}, base...), "flag provided but not defined"},
		"stray argument":    {append([]string{"run", "--corpus", corpus, "stray"}, base...), "unexpected argument"},
		"negative run time": {append([]string{"run", "--corpus", corpus, "--run-timeout", "-1s"}, base...), "--run-timeout"},
	} {
		t.Run(name, func(t *testing.T) {
			res := runCLI(t, nil, tc.args...)
			if res.code != eval.ExitUsage || !strings.Contains(res.stderr, tc.want) || res.stdout != "" {
				t.Fatalf("%+v, want exit %d with %q", res, eval.ExitUsage, tc.want)
			}
		})
	}
	if len(svc.Seen()) != 0 {
		t.Fatal("a usage error must not send requests")
	}
}

func TestCLIExitCodesForRequestErrorsAndAbort(t *testing.T) {
	svc, corpus := cliFixture(t)
	svc.Override = func(w http.ResponseWriter, _ *http.Request, req received) bool {
		if req.Body.Texts[0] == "clean" {
			w.WriteHeader(http.StatusInternalServerError)
			return true
		}
		return false
	}
	res := runCLI(t, nil, "run", "--corpus", corpus, "--base-url", svc.Server.URL, "--format", "json")
	if res.code != eval.ExitRequestErrors || !strings.Contains(res.stderr, "1 request errors") || !json.Valid([]byte(res.stdout)) {
		t.Fatalf("%+v", res)
	}

	svc.Override = func(w http.ResponseWriter, _ *http.Request, _ received) bool {
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	res = runCLI(t, nil, "run", "--corpus", corpus, "--base-url", svc.Server.URL, "--format", "json")
	if res.code != eval.ExitAborted || !strings.Contains(res.stderr, "HTTP 401") || !strings.Contains(res.stdout, `"status": "aborted"`) {
		t.Fatalf("%+v", res)
	}
}

func TestCLIAPIKeyFromEnvironmentOrFileNeverEchoed(t *testing.T) {
	const key = "demo-key-abcdef-123456"
	svc, corpus := cliFixture(t)
	keyFile := writeFile(t, "key", key+"\n")

	for name, tc := range map[string]struct {
		env  map[string]string
		args []string
		auth func(received) bool
	}{
		"env bearer":     {map[string]string{eval.EnvAPIKey: key}, nil, func(r received) bool { return r.Authorization == "Bearer "+key && r.APIKey == "" }},
		"file bearer":    {nil, []string{"--api-key-file", keyFile}, func(r received) bool { return r.Authorization == "Bearer "+key }},
		"file x-api-key": {nil, []string{"--api-key-file", keyFile, "--auth-scheme", "x-api-key"}, func(r received) bool { return r.APIKey == key && r.Authorization == "" }},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(svc.Seen())
			args := append([]string{"run", "--corpus", corpus, "--base-url", svc.Server.URL, "--format", "json"}, tc.args...)
			res := runCLI(t, tc.env, args...)
			if res.code != eval.ExitOK {
				t.Fatalf("%+v", res)
			}
			if got := svc.Seen()[before]; !tc.auth(got) {
				t.Fatalf("request = %+v", got)
			}
			if strings.Contains(res.stdout, key) || strings.Contains(res.stderr, key) {
				t.Fatal("the API key was echoed")
			}
		})
	}

	// Failure paths must not echo the key either.
	for name, tc := range map[string]struct {
		env  map[string]string
		args []string
		want string
	}{
		"both sources":       {map[string]string{eval.EnvAPIKey: key}, []string{"--api-key-file", keyFile}, "use only one"},
		"empty file":         {nil, []string{"--api-key-file", writeFile(t, "empty", " \n")}, "empty"},
		"missing file":       {nil, []string{"--api-key-file", filepath.Join(t.TempDir(), "none")}, "cannot open"},
		"oversize file":      {nil, []string{"--api-key-file", writeFile(t, "big", strings.Repeat("k", 5000))}, "exceeds"},
		"key in remote http": {map[string]string{eval.EnvAPIKey: key}, []string{"--base-url", "http://guardrail.example.org"}, "plain http"},
	} {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"run", "--corpus", corpus, "--base-url", svc.Server.URL}, tc.args...)
			res := runCLI(t, tc.env, args...)
			if res.code != eval.ExitUsage || !strings.Contains(res.stderr, tc.want) || strings.Contains(res.stderr+res.stdout, key) {
				t.Fatalf("%+v", res)
			}
		})
	}
}

func TestCLIUnwritableOutputIsAFailureNotAUsageError(t *testing.T) {
	svc, corpus := cliFixture(t)
	res := runCLI(t, nil, "run", "--corpus", corpus, "--base-url", svc.Server.URL, "--output", filepath.Join(t.TempDir(), "missing-dir", "r.json"))
	if res.code != eval.ExitFailure || !strings.Contains(res.stderr, "write report") {
		t.Fatalf("%+v", res)
	}
}

func TestCLIValidateAndHelp(t *testing.T) {
	_, corpus := cliFixture(t)
	res := runCLI(t, nil, "validate", "--corpus", corpus)
	if res.code != eval.ExitOK || !strings.Contains(res.stdout, "unit: 2 cases, detectors [detect_pii], languages [en fr]") {
		t.Fatalf("%+v", res)
	}
	if res := runCLI(t, nil, "validate", "--corpus", writeFile(t, "bad.jsonl", "{}\n")); res.code != eval.ExitUsage {
		t.Fatalf("%+v", res)
	}
	if res := runCLI(t, nil, "validate"); res.code != eval.ExitUsage {
		t.Fatalf("%+v", res)
	}
	if res := runCLI(t, nil, "help"); res.code != eval.ExitOK || !strings.Contains(res.stdout, "Usage:") {
		t.Fatalf("%+v", res)
	}
	if res := runCLI(t, nil, "run", "-h"); res.code != eval.ExitOK {
		t.Fatalf("%+v", res)
	}
}
