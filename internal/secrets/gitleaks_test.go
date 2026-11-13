package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

func TestVendoredRulesProvenance(t *testing.T) {
	body, err := gitleaksBody(gitleaksRulesFile)
	if err != nil {
		t.Fatal(err)
	}
	// The vendored body lacks only the upstream final empty line.
	sum := sha256.Sum256([]byte(body + "\n"))
	if got := hex.EncodeToString(sum[:]); got != GitleaksUpstreamSHA256 {
		t.Fatalf("vendored rules differ from upstream %s@%s: sha256 %s", GitleaksVersion, GitleaksCommit, got)
	}
	header, _, _ := strings.Cut(gitleaksRulesFile, gitleaksBodyMarker)
	for _, want := range []string{GitleaksVersion, GitleaksCommit, GitleaksUpstreamSHA256, "MIT", "Copyright (c) 2019 Zachary Rice"} {
		if !strings.Contains(header, want) {
			t.Errorf("rules file header lacks %q", want)
		}
	}
}

func TestVendoredRulesLoadCompletely(t *testing.T) {
	set, err := defaultGitleaksRules()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := gitleaksBody(gitleaksRulesFile)
	upstream := strings.Count(body, "\n[[rules]]\n")
	if got := len(set.rules) + len(set.excluded); got != upstream {
		t.Fatalf("loaded %d + excluded %d rules, upstream defines %d", len(set.rules), len(set.excluded), upstream)
	}
	if len(set.rules) != 217 {
		t.Errorf("active rules = %d, want 217", len(set.rules))
	}
	wantExcluded := []string{"freemius-secret-key", "hashicorp-tf-password", "kubernetes-secret-yaml", "nuget-config-password", "pkcs12-file"}
	if len(set.excluded) != len(wantExcluded) {
		t.Fatalf("excluded = %v, want %v", set.excluded, wantExcluded)
	}
	for i, id := range wantExcluded {
		if set.excluded[i].ID != id || set.excluded[i].Reason == "" {
			t.Errorf("excluded[%d] = %+v, want %s with a reason", i, set.excluded[i], id)
		}
	}
	if len(set.global) != 1 || len(set.global[0].regexes) == 0 || len(set.global[0].stopwords) == 0 {
		t.Errorf("global allowlist not loaded: %+v", set.global)
	}
	for _, rule := range set.rules {
		// Every regex compiled with Go's RE2 engine; RE2 has no lookaround.
		if strings.Contains(rule.regex.String(), "(?=") || strings.Contains(rule.regex.String(), "(?!") {
			t.Errorf("rule %s uses lookahead", rule.id)
		}
	}
}

func mustRules(t *testing.T, config string) *gitleaksRuleSet {
	t.Helper()
	set, err := loadGitleaksRules(config)
	if err != nil {
		t.Fatalf("loadGitleaksRules: %v", err)
	}
	return set
}

func scanWith(t *testing.T, set *gitleaksRuleSet, text string) []rawFinding {
	t.Helper()
	findings, err := scanGitleaks(context.Background(), newTextView(text), set.rules, set.global)
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

func spans(findings []rawFinding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.rule + ":" + strconv.Itoa(f.start) + "-" + strconv.Itoa(f.end)
	}
	return out
}

func expectSpans(t *testing.T, name string, got []rawFinding, want ...string) {
	t.Helper()
	if strings.Join(spans(got), " ") != strings.Join(want, " ") {
		t.Errorf("%s: got %v, want %v", name, spans(got), want)
	}
}

func TestGitleaksSecretGroupSelection(t *testing.T) {
	set := mustRules(t, `
[[rules]]
id = "explicit"
regex = '''(a)-(b+)'''
secretGroup = 2

[[rules]]
id = "first-non-empty"
regex = '''x(y?)(z+)'''

[[rules]]
id = "whole"
regex = '''q{3}'''
`)
	expectSpans(t, "explicit group", scanWith(t, set, "a-bbb"), "gitleaks:explicit:2-5")
	expectSpans(t, "first non-empty group", scanWith(t, set, "xzz"), "gitleaks:first-non-empty:1-3")
	expectSpans(t, "first group", scanWith(t, set, "xyzz"), "gitleaks:first-non-empty:1-2")
	expectSpans(t, "no group", scanWith(t, set, " qqq "), "gitleaks:whole:1-4")
}

func TestGitleaksKeywordsAndEntropy(t *testing.T) {
	set := mustRules(t, `
[[rules]]
id = "kw"
regex = '''tok_[a-z0-9]{8}'''
entropy = 2.9
keywords = ["TOK_"]
`)
	// Keywords are lower-cased and compared with the lower-cased text.
	expectSpans(t, "keyword present", scanWith(t, set, "TOK_ tok_a1b2c3d4"), "gitleaks:kw:5-17")
	// Entropy must be strictly greater than the rule threshold.
	expectSpans(t, "low entropy", scanWith(t, set, "tok_aaaabbbb")) // 1 bit
	// The secret group abcdefgh has exactly 3 bits: kept above 2.9,
	// dropped at 3.0 (gitleaks skips entropy <= threshold).
	group := func(threshold string) *gitleaksRuleSet {
		return mustRules(t, "[[rules]]\nid = \"kw\"\nregex = '''tok_([a-z]{8})'''\nentropy = "+threshold+"\n")
	}
	expectSpans(t, "entropy above threshold", scanWith(t, group("2.9"), "tok_abcdefgh"), "gitleaks:kw:4-12")
	expectSpans(t, "entropy equal to threshold", scanWith(t, group("3.0"), "tok_abcdefgh"))
}

func TestGitleaksKeywordPrefilterSkipsRule(t *testing.T) {
	set := mustRules(t, "[[rules]]\nid = \"kw\"\nregex = '''[0-9]{6}'''\nkeywords = [\"pin\"]\n")
	expectSpans(t, "no keyword", scanWith(t, set, "code 123456"))
	expectSpans(t, "keyword", scanWith(t, set, "PIN 123456"), "gitleaks:kw:4-10")
}

func TestGitleaksTrimsNewlines(t *testing.T) {
	set := mustRules(t, "[[rules]]\nid = \"nl\"\nregex = '''\\n?K[0-9]{4}\\n?'''\n")
	expectSpans(t, "trimmed", scanWith(t, set, "a\nK1234\nb"), "gitleaks:nl:2-7")
}

func TestGitleaksAllowlists(t *testing.T) {
	set := mustRules(t, `
[allowlist]
regexes = ['''^GLOBAL''']
stopwords = ["sample"]

[[rules]]
id = "r"
regex = '''key=([A-Za-z0-9]+)'''
[[rules.allowlists]]
regexes = ['''^ALLOW''']
[[rules.allowlists]]
regexTarget = "match"
regexes = ['''^key=MATCH''']
[[rules.allowlists]]
regexTarget = "line"
regexes = ['''# ignore-line''']
[[rules.allowlists]]
condition = "AND"
paths = ['''\.txt$''']
regexes = ['''^PATHAND''']
[[rules.allowlists]]
paths = ['''.*''']
`)
	cases := map[string]bool{
		"key=GLOBAL1":                     false, // global regex on the secret
		"key=xSAMPLEx":                    false, // stopwords are case-insensitive
		"key=ALLOW1":                      false, // rule regex on the secret
		"key=MATCH1":                      false, // regexTarget match
		"key=Line1 # ignore-line":         false, // regexTarget line
		"other\nkey=Line2\n# ignore-line": true,  // line target is the match line only
		"key=PATHAND1":                    true,  // AND with a path never matches text
		"key=Real1":                       true,  // an OR path-only allowlist never matches text
	}
	for text, reported := range cases {
		got := len(scanWith(t, set, text)) > 0
		if got != reported {
			t.Errorf("%q: reported=%v, want %v", text, got, reported)
		}
	}
}

func TestGitleaksGenericPrecedence(t *testing.T) {
	set := mustRules(t, `
[[rules]]
id = "generic-thing"
regex = '''token=([a-z0-9_]+)'''

[[rules]]
id = "provider"
regex = '''prov_[a-z0-9]+'''
`)
	expectSpans(t, "same line", scanWith(t, set, "token=prov_abc123"), "gitleaks:provider:6-17")
	expectSpans(t, "other line keeps generic", scanWith(t, set, "token=abc123\nprov_abc"), "gitleaks:generic-thing:6-12", "gitleaks:provider:13-21")
}

func TestGitleaksInlineAllowIsIgnored(t *testing.T) {
	// gitleaks honours a "gitleaks:allow" comment on the line. In user
	// supplied text that would be a trivial bypass, so it is not supported.
	set := mustRules(t, "[[rules]]\nid = \"r\"\nregex = '''prov_[a-z0-9]{6}'''\n")
	expectSpans(t, "gitleaks:allow", scanWith(t, set, "prov_abc123 # gitleaks:allow"), "gitleaks:r:0-11")
}

func TestGitleaksPathScopedRules(t *testing.T) {
	set := mustRules(t, `
[[rules]]
id = "php-only"
regex = '''x'''
path = '''\.php$'''
[[rules.allowlists]]
regexes = ['''y''']

[[rules]]
id = "any-path"
regex = '''z'''
path = '''.*'''
`)
	if len(set.excluded) != 1 || set.excluded[0].ID != "php-only" {
		t.Fatalf("excluded = %+v", set.excluded)
	}
	if len(set.rules) != 1 || set.rules[0].id != "any-path" || len(set.rules[0].allowlists) != 0 {
		t.Fatalf("a path regex matching the empty path keeps the rule, without the excluded rule's allowlist: %+v", set.rules)
	}
}

func TestGitleaksConfigErrors(t *testing.T) {
	cases := map[string]string{
		"lookahead":           "[[rules]]\nid = \"la\"\nregex = '''a(?=b)'''\n",
		"unknown rule key":    "[[rules]]\nid = \"u\"\nregex = '''a'''\nskipReport = true\n",
		"unknown table":       "[[rules]]\nid = \"u\"\nregex = '''a'''\n[[rules.required]]\nid = \"x\"\n",
		"duplicate id":        "[[rules]]\nid = \"d\"\nregex = '''a'''\n[[rules]]\nid = \"d\"\nregex = '''b'''\n",
		"missing id":          "[[rules]]\nregex = '''a'''\n",
		"no regex nor path":   "[[rules]]\nid = \"n\"\n",
		"secret group range":  "[[rules]]\nid = \"g\"\nregex = '''(a)'''\nsecretGroup = 2\n",
		"empty allowlist":     "[[rules]]\nid = \"e\"\nregex = '''a'''\n[[rules.allowlists]]\ndescription = \"x\"\n",
		"bad condition":       "[[rules]]\nid = \"c\"\nregex = '''a'''\n[[rules.allowlists]]\ncondition = \"XOR\"\nregexes = ['''b''']\n",
		"bad target":          "[[rules]]\nid = \"t\"\nregex = '''a'''\n[[rules.allowlists]]\nregexTarget = \"file\"\nregexes = ['''b''']\n",
		"entropy type":        "[[rules]]\nid = \"t\"\nregex = '''a'''\nentropy = \"high\"\n",
		"no rules":            "title = \"empty\"\n",
		"allowlist first":     "[[rules.allowlists]]\nregexes = ['''b''']\n",
		"targetRules":         "[[allowlists]]\ntargetRules = [\"x\"]\nregexes = ['''b''']\n[[rules]]\nid = \"x\"\nregex = '''a'''\n",
		"bad allowlist regex": "[allowlist]\nregexes = ['''(?<=a)b''']\n[[rules]]\nid = \"x\"\nregex = '''a'''\n",
	}
	for name, config := range cases {
		if _, err := loadGitleaksRules(config); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	_, err := loadGitleaksRules("[[rules]]\nid = \"la\"\nregex = '''a(?=b)'''\n")
	if err == nil || !strings.Contains(err.Error(), "rule la") || !strings.Contains(err.Error(), "RE2") {
		t.Errorf("RE2 error must name the rule: %v", err)
	}
}

func TestDisabledRules(t *testing.T) {
	cfg := gitleaksOnly()
	cfg.Gitleaks.DisabledRules = []string{"github-pat"}
	scanner := mustScanner(t, cfg)
	text := "ghp_" + newFixtureGen(3).pick(alphaAlnum, 36)
	for _, f := range scan(t, scanner, text) {
		if f.Rule == "gitleaks:github-pat" {
			t.Fatal("disabled rule reported")
		}
	}
	for _, rule := range scanner.Rules() {
		if rule == "gitleaks:github-pat" {
			t.Fatal("disabled rule listed")
		}
	}
	for _, ids := range [][]string{{"no-such-rule"}, {"pkcs12-file"}} {
		cfg.Gitleaks.DisabledRules = ids
		if _, err := New(cfg); err == nil {
			t.Errorf("disabling %v must fail", ids)
		}
	}
}
