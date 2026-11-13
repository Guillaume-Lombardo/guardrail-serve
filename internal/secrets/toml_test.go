package secrets

import (
	"reflect"
	"strings"
	"testing"
)

func TestTOMLSubsetValues(t *testing.T) {
	tables, err := parseTOMLSubset(`# comment
title = "a \"quoted\" \\ title \u00e9" # trailing comment
minVersion = 'v8.25.0'

[[rules]]
id = "r1"
regex = '''(?i)a'b'''
entropy = 3.5
secretGroup = 2
keywords = [
    "one", # first
    '''two''',
    'three',
]
[[rules.allowlists]]
regexes = []
stopwords = ["x"]
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) != 3 || tables[1].kind != tomlRule || tables[2].kind != tomlRuleAllowlist {
		t.Fatalf("tables = %+v", tables)
	}
	if got := tables[0].values["title"].str; got != `a "quoted" \ title é` {
		t.Errorf("basic string = %q", got)
	}
	rule := tables[1].values
	if rule["regex"].str != `(?i)a'b` || rule["entropy"].kind != tomlFloat || rule["entropy"].num != 3.5 {
		t.Errorf("rule values = %+v", rule)
	}
	if rule["secretGroup"].kind != tomlInteger || rule["secretGroup"].integer != 2 {
		t.Errorf("secretGroup = %+v", rule["secretGroup"])
	}
	if !reflect.DeepEqual(rule["keywords"].strs, []string{"one", "two", "three"}) {
		t.Errorf("keywords = %v", rule["keywords"].strs)
	}
}

func TestTOMLSubsetRejectsUnsupportedSyntax(t *testing.T) {
	cases := map[string]string{
		"unknown table":           "[extend]\n",
		"duplicate single table":  "[allowlist]\n[allowlist]\n",
		"duplicate key":           "a = 1\na = 2\n",
		"multi-line basic string": "a = \"\"\"x\"\"\"\n",
		"multi-line literal":      "a = '''x\ny'''\n",
		"unterminated string":     "a = \"x\n",
		"unknown escape":          "a = \"\\q\"\n",
		"nested array":            "a = [[\"x\"]]\n",
		"mixed array":             "a = [\"x\", 1]\n",
		"exponent float":          "a = 1e3\n",
		"inline table":            "a = {b = 1}\n",
		"dotted key":              "a.b = 1\n",
		"trailing content":        "a = 1 2\n",
		"missing equals":          "a 1\n",
		"invalid utf8":            "a = \"\xff\"\n",
		"ambiguous literal":       "a = '''x''''\n",
	}
	for name, src := range cases {
		if _, err := parseTOMLSubset(src); err == nil {
			t.Errorf("%s: expected an error", name)
		} else if !strings.Contains(err.Error(), "line") && name != "invalid utf8" {
			t.Errorf("%s: error must carry a line number: %v", name, err)
		}
	}
}
