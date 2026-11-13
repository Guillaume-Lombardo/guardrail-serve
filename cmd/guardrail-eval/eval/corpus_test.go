package eval_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

const validHeader = `{"format":"guardrail-eval-corpus","version":1,"name":"unit"}` + "\n"

func parse(t *testing.T, body string) (*eval.Corpus, error) {
	t.Helper()
	return eval.ParseCorpus(strings.NewReader(body))
}

func TestParseCorpusAppliesDefaultsAndDigest(t *testing.T) {
	body := validHeader + `{"id":"a-1","lang":"fr","text":"Bonjour é","labels":{"detect_pii":false,"detect_secret":true},"tags":["hard"]}` + "\n\n"
	corpus, err := parse(t, body)
	if err != nil {
		t.Fatal(err)
	}
	if got := corpus.Cases[0].InputType; got != eval.InputRequest {
		t.Fatalf("input_type default = %q", got)
	}
	if corpus.Header.Name != "unit" || len(corpus.Cases) != 1 || len(corpus.SHA256) != 64 {
		t.Fatalf("corpus = %+v", corpus)
	}
	if detectors := strings.Join(corpus.Detectors(), ","); detectors != "detect_pii,detect_secret" {
		t.Fatalf("detectors = %s", detectors)
	}
	again, _ := parse(t, body)
	if again.SHA256 != corpus.SHA256 {
		t.Fatal("digest is not deterministic")
	}
}

func TestParseCorpusRejectsInvalidInput(t *testing.T) {
	good := `{"id":"a-1","lang":"en","text":"hello","labels":{"detect_pii":true}}`
	cases := map[string]struct{ body, want string }{
		"empty":          {"", "missing header"},
		"no cases":       {validHeader, "no cases"},
		"bad format":     {`{"format":"other","version":1,"name":"unit"}` + "\n" + good, "format must be"},
		"future version": {`{"format":"guardrail-eval-corpus","version":2,"name":"unit"}` + "\n" + good, "unsupported corpus version 2"},
		"bad name":       {`{"format":"guardrail-eval-corpus","version":1,"name":"Bad Name"}` + "\n" + good, "name"},
		"header unknown": {`{"format":"guardrail-eval-corpus","version":1,"name":"unit","extra":1}` + "\n" + good, "unknown field"},
		"case unknown":   {validHeader + `{"id":"a-1","lang":"en","text":"x","labels":{"detect_pii":true},"expected":1}`, "line 2"},
		"trailing data":  {validHeader + good + ` {}`, "unexpected data"},
		"trailing brace": {validHeader + good + `}`, "unexpected data"},
		"null label":     {validHeader + `{"id":"a","lang":"en","text":"x","labels":{"detect_pii":null}}`, "must be true or false"},
		"not json":       {validHeader + "nope", "line 2"},
		"duplicate id":   {validHeader + good + "\n" + good, "duplicate case id"},
		"bad id":         {validHeader + `{"id":"A B","lang":"en","text":"x","labels":{"detect_pii":true}}`, "id must match"},
		"bad lang":       {validHeader + `{"id":"a","lang":"english","text":"x","labels":{"detect_pii":true}}`, "lang"},
		"bad input type": {validHeader + `{"id":"a","lang":"en","input_type":"both","text":"x","labels":{"detect_pii":true}}`, "input_type"},
		"blank text":     {validHeader + `{"id":"a","lang":"en","text":"  \n","labels":{"detect_pii":true}}`, "blank"},
		"no labels":      {validHeader + `{"id":"a","lang":"en","text":"x","labels":{}}`, "labels"},
		"bad detector":   {validHeader + `{"id":"a","lang":"en","text":"x","labels":{"Detect PII":true}}`, "detector"},
		"label not bool": {validHeader + `{"id":"a","lang":"en","text":"x","labels":{"detect_pii":"yes"}}`, "line 2"},
		"duplicate tag":  {validHeader + `{"id":"a","lang":"en","text":"x","labels":{"detect_pii":true},"tags":["t","t"]}`, "duplicate tag"},
		"bad tag":        {validHeader + `{"id":"a","lang":"en","text":"x","labels":{"detect_pii":true},"tags":["Bad Tag"]}`, "tag"},
		"text too long":  {validHeader + `{"id":"a","lang":"en","text":"` + strings.Repeat("é", eval.MaxCaseRunes+1) + `","labels":{"detect_pii":true}}`, "limit is"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parse(t, tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestWriteCorpusRoundTripsCanonically(t *testing.T) {
	header := eval.Header{Name: "round-trip", Source: &eval.Source{Dataset: "demo"}}
	cases := []eval.Case{
		{ID: "a-1", Lang: "fr", Text: "<b>é & ü</b>", Labels: map[string]bool{"prompt_injection": true, "detect_pii": false}, Tags: []string{"x"}},
		{ID: "a-2", Lang: "en", InputType: eval.InputResponse, Text: "ok", Labels: map[string]bool{"detect_pii": false}},
	}
	var first bytes.Buffer
	if err := eval.WriteCorpus(&first, header, cases); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(first.String(), "<b>") || strings.Contains(first.String(), "\\u003"+"c") {
		t.Fatalf("HTML characters must not be escaped: %s", first.String())
	}
	corpus, err := parse(t, first.String())
	if err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err := eval.WriteCorpus(&second, corpus.Header, corpus.Cases); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatalf("not canonical:\n%s\n%s", first.String(), second.String())
	}
}

func TestWriteCorpusRejectsInvalidData(t *testing.T) {
	valid := eval.Case{ID: "a", Lang: "en", Text: "x", Labels: map[string]bool{"detect_pii": true}}
	for name, tc := range map[string]struct {
		header eval.Header
		cases  []eval.Case
	}{
		"no cases":      {eval.Header{Name: "n"}, nil},
		"bad header":    {eval.Header{Name: "N!"}, []eval.Case{valid}},
		"duplicate ids": {eval.Header{Name: "n"}, []eval.Case{valid, valid}},
		"bad case":      {eval.Header{Name: "n"}, []eval.Case{{ID: "a"}}},
		"invalid utf-8": {eval.Header{Name: "n"}, []eval.Case{{ID: "a", Lang: "en", Text: "\xff", Labels: map[string]bool{"detect_pii": true}}}},
	} {
		if err := eval.WriteCorpus(&bytes.Buffer{}, tc.header, tc.cases); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadCorpusMissingFile(t *testing.T) {
	if _, err := eval.LoadCorpus(t.TempDir() + "/missing.jsonl"); err == nil {
		t.Fatal("expected an error")
	}
}
