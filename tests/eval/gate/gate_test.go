package gate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

func fixture() (*eval.Corpus, *Snapshot) {
	c := &eval.Corpus{Header: eval.Header{Name: "fixture"}, SHA256: strings.Repeat("a", 64), Cases: []eval.Case{
		{ID: "correct", Lang: "fr", Labels: map[string]bool{"detect_secret": true}},
		{ID: "missed", Lang: "fr", Labels: map[string]bool{"detect_secret": true}},
		{ID: "negative", Lang: "en", Labels: map[string]bool{"detect_secret": false}},
	}}
	s := &Snapshot{Version: 1, Corpus: c.Header.Name, SHA256: c.SHA256, Mode: eval.ModeAnnotate, Policy: "audit", Outcomes: map[string]map[string]bool{
		"correct": {"detect_secret": true}, "missed": {"detect_secret": false}, "negative": {"detect_secret": false},
	}}
	refresh(s, c)
	return c, s
}
func refresh(s *Snapshot, c *eval.Corpus) { s.Groups, s.KnownFailures, _ = summarize(s, c) }

func TestCompare(t *testing.T) {
	for _, name := range []string{"equal", "improvement", "regression", "compensated", "missing case", "missing label", "identity", "summary", "undefined current", "undefined baseline"} {
		t.Run(name, func(t *testing.T) {
			c, b := fixture()
			_, s := fixture()
			wantFailure := true
			switch name {
			case "equal":
				wantFailure = false
			case "improvement":
				s.Outcomes["missed"]["detect_secret"] = true
				wantFailure = false
			case "regression", "undefined current":
				s.Outcomes["correct"]["detect_secret"] = false
			case "compensated":
				s.Outcomes["correct"]["detect_secret"] = false
				s.Outcomes["missed"]["detect_secret"] = true
			case "missing case":
				delete(s.Outcomes, "correct")
			case "missing label":
				delete(s.Outcomes["correct"], "detect_secret")
			case "identity":
				s.SHA256 = "changed"
			case "undefined baseline":
				b.Outcomes["correct"]["detect_secret"] = false
				refresh(b, c)
				wantFailure = false
			}
			refresh(s, c)
			if name == "summary" {
				s.Groups["detect_secret"]["fr"] = eval.GroupResult{}
			}
			got := Compare(b, s, c)
			if (len(got) > 0) != wantFailure {
				t.Fatalf("violations: %v", got)
			}
			if name == "compensated" && (!reflect.DeepEqual(b.Groups, s.Groups) || !strings.Contains(strings.Join(got, " "), "previously correct")) {
				t.Fatal("compensating improvement hid regression", got)
			}
		})
	}
}

func TestMeasureErrorsAreNotNegatives(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusOK} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte("invalid json"))
		}))
		client, err := eval.NewClient(eval.ClientConfig{BaseURL: server.URL, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		c, _ := fixture()
		if s, err := Measure(context.Background(), client, c); err == nil || s != nil {
			t.Fatal("request failure became detection outcome")
		}
		server.Close()
		if s, err := Measure(context.Background(), client, c); err == nil || s != nil {
			t.Fatal("transport failure became detection outcome")
		}
	}
}

// A child test process is the same failure boundary used by the workflow:
// a degraded HTTP observation must make go test exit nonzero.
func TestInjectedDegradationExitsNonzero(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestDegradedGateProcess$")
	cmd.Env = append(os.Environ(), "EVAL_GATE_FAILURE_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "previously correct case regressed") || !strings.Contains(string(output), "threshold regressed") {
		t.Fatalf("expected failing gate process, got %v: %s", err, output)
	}
}
func TestDegradedGateProcess(t *testing.T) {
	if os.Getenv("EVAL_GATE_FAILURE_CHILD") != "1" {
		t.Skip("subprocess helper")
	}
	c, b := fixture()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"findings": []any{}, "decision": "NONE"})
	}))
	defer server.Close()
	client, err := eval.NewClient(eval.ClientConfig{BaseURL: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	s, err := Measure(context.Background(), client, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, violation := range Compare(b, s, c) {
		t.Error(violation)
	}
}

func TestCheckFloors(t *testing.T) {
	// fixture: fr recall 1/2 and no fr negatives; en has one true negative.
	c, s := fixture()
	floor := func(lang string, recall, fpr float64) []Floor {
		return []Floor{{Detector: "detect_secret", Lang: lang, MinRecall: recall, MaxFPR: fpr}}
	}
	for _, tc := range []struct {
		name   string
		floors []Floor
		mutate func()
		want   []string
	}{
		{"recall at floor", floor("all", 0.5, 0), nil, []string{}},
		{"recall below floor", floor("all", 0.85, 0.05), nil, []string{"floor recall missed: detect_secret/all 0.500000 < 0.850000"}},
		{"fpr above floor", floor("all", 0, 0.05), func() { s.Outcomes["negative"]["detect_secret"] = true }, []string{"floor fpr exceeded: detect_secret/all 1.000000 > 0.050000"}},
		{"undefined fpr fails", floor("fr", 0, 0.05), nil, []string{"floor fpr undefined: detect_secret/fr"}},
		{"undefined recall fails", floor("en", 0, 1), nil, []string{"floor recall undefined: detect_secret/en"}},
		{"missing group fails", floor("de", 0, 1), nil, []string{"floor group missing: detect_secret/de"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, s = fixture()
			if tc.mutate != nil {
				tc.mutate()
			}
			refresh(s, c)
			if got := CheckFloors(s, tc.floors); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
