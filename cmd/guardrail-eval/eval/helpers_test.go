package eval_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// writeFile writes content into a per-test temporary directory.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// corpusFile writes a corpus named name with the given case lines.
func corpusFile(t *testing.T, name string, lines ...string) string {
	t.Helper()
	header := `{"format":"guardrail-eval-corpus","version":1,"name":"` + name + `"}`
	return writeFile(t, name+".jsonl", header+"\n"+strings.Join(lines, "\n")+"\n")
}

// caseLine builds a case line. labels is a JSON object body such as `"detect_pii":true`.
func caseLine(id, lang, text, labels string, extra ...string) string {
	encoded, _ := json.Marshal(text)
	line := `{"id":"` + id + `","lang":"` + lang + `","text":` + string(encoded) + `,"labels":{` + labels + `}`
	for _, field := range extra {
		line += "," + field
	}
	return line + "}"
}

// received records one request seen by a fake service.
type received struct {
	Method, Path, Authorization, APIKey, ContentType string
	Body                                             struct {
		Texts     []string `json:"texts"`
		InputType string   `json:"input_type"`
	}
}

// fakeService answers /v1/guardrails/{policy} with findings looked up by text
// and /scan/* with a decision looked up by route and text. It records requests.
type fakeService struct {
	t        *testing.T
	Server   *httptest.Server
	mu       sync.Mutex
	requests []received
	// Findings maps text to detector names reported by the policy route.
	Findings map[string][]string
	// Scans maps route+"|"+text to a decision; missing means NONE.
	Scans map[string]string
	// Override, when set, handles the request instead of the defaults.
	Override func(w http.ResponseWriter, r *http.Request, req received) bool
}

func newFakeService(t *testing.T) *fakeService {
	t.Helper()
	f := &fakeService{t: t, Findings: map[string][]string{}, Scans: map[string]string{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Server.Close)
	return f
}

func (f *fakeService) serve(w http.ResponseWriter, r *http.Request) {
	req := received{
		Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization"),
		APIKey: r.Header.Get("X-API-Key"), ContentType: r.Header.Get("Content-Type"),
	}
	if err := json.NewDecoder(r.Body).Decode(&req.Body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()
	if f.Override != nil && f.Override(w, r, req) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	text := req.Body.Texts[0]
	if strings.Contains(r.URL.Path, "/v1/guardrails/") {
		findings := []map[string]any{}
		for _, detector := range f.Findings[text] {
			findings = append(findings, map[string]any{"text_index": 0, "detector": detector, "type": "X", "rule": "r", "start": 0, "end": 1, "action": "annotate"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"policy": "audit", "mode": "detect", "stage": "input", "decision": "NONE", "policy_decision": "NONE", "texts": req.Body.Texts, "findings": findings})
		return
	}
	decision := f.Scans[r.URL.Path+"|"+text]
	if decision == "" {
		decision = "NONE"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"decision": decision, "texts": req.Body.Texts, "metadata": map[string]any{"guardrail": "x"}})
}

// Seen returns a copy of the requests received so far.
func (f *fakeService) Seen() []received {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]received(nil), f.requests...)
}
