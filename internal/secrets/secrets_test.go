package secrets

import (
	"context"
	"errors"
	"math"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestNewValidatesConfig(t *testing.T) {
	valid := DefaultConfig()
	cases := map[string]func(*Config){
		"nothing enabled":              func(c *Config) { *c = Config{} },
		"disabled rules without rules": func(c *Config) { c.Gitleaks.Enabled = false; c.Gitleaks.DisabledRules = []string{"github-pat"} },
		"zero base64 threshold":        func(c *Config) { c.Entropy.Base64Threshold = 0 },
		"NaN hex threshold":            func(c *Config) { c.Entropy.HexThreshold = math.NaN() },
		"threshold above 8":            func(c *Config) { c.Entropy.HexThreshold = 8.5 },
		"zero minimum length":          func(c *Config) { c.Entropy.MinBase64Length = 0 },
	}
	for name, mutate := range cases {
		cfg := valid
		cfg.Gitleaks.DisabledRules = nil
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// Disabled sources are not validated.
	cfg := valid
	cfg.Entropy = EntropyConfig{}
	if _, err := New(cfg); err != nil {
		t.Errorf("entropy disabled: %v", err)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Gitleaks.Enabled || !cfg.Keywords.Enabled || !cfg.Entropy.Enabled ||
		cfg.Entropy.Base64Threshold != 4.5 || cfg.Entropy.HexThreshold != 3.0 ||
		cfg.Entropy.MinBase64Length != 20 || cfg.Entropy.MinHexLength != 16 {
		t.Fatalf("DefaultConfig = %+v", cfg)
	}
}

func TestRulesListing(t *testing.T) {
	rules := mustScanner(t, DefaultConfig()).Rules()
	if !sort.StringsAreSorted(rules) {
		t.Error("rules are not sorted")
	}
	if len(rules) != 217+len(keywordRuleNames())+2 {
		t.Errorf("len(Rules) = %d", len(rules))
	}
	for _, want := range []string{"gitleaks:aws-access-token", "keyword:password", "keyword:bearer", "entropy:base64", "entropy:hex"} {
		if i := sort.SearchStrings(rules, want); i == len(rules) || rules[i] != want {
			t.Errorf("Rules lacks %s", want)
		}
	}
	excluded, err := ExcludedGitleaksRules()
	if err != nil || len(excluded) != 5 {
		t.Errorf("ExcludedGitleaksRules = %v, %v", excluded, err)
	}
}

func TestOffsetsAreRunes(t *testing.T) {
	scanner := mustScanner(t, DefaultConfig())
	token := "ghp_" + newFixtureGen(11).pick(alphaAlnum, 36)
	text := "Clé d'accès 🔐 pour l'équipe : " + token + " — merci\npassword=" + contextValue
	findings := scan(t, scanner, text)
	if len(findings) != 2 {
		t.Fatalf("findings = %s", describe(findings))
	}
	runes := []rune(text)
	for _, f := range findings {
		if string(runes[f.Start:f.End]) != text[f.ByteStart:f.ByteEnd] {
			t.Errorf("%s: rune span [%d,%d) and byte span [%d,%d) disagree", f.Rule, f.Start, f.End, f.ByteStart, f.ByteEnd)
		}
		if !utf8.RuneStart(text[f.ByteStart]) {
			t.Errorf("%s: byte start is not on a rune boundary", f.Rule)
		}
	}
	if got := string(runes[findings[0].Start:findings[0].End]); got != token {
		t.Errorf("first finding covers %d runes, want the token", len([]rune(got)))
	}
	if findings[0].Start != utf8.RuneCountInString(text[:strings.Index(text, token)]) {
		t.Errorf("start %d is not a rune offset", findings[0].Start)
	}
	if findings[0].Source != SourceGitleaks || findings[0].Type != TypeSecret || findings[0].Score != nil {
		t.Errorf("first finding = %+v", findings[0])
	}
	if findings[1].Source != SourceKeyword || findings[1].Rule != "keyword:password" {
		t.Errorf("second finding = %+v", findings[1])
	}
}

func TestInvalidUTF8CountsOneRunePerByte(t *testing.T) {
	scanner := mustScanner(t, keywordsOnly())
	text := "\xff\xfepassword=" + contextValue
	findings := scan(t, scanner, text)
	if len(findings) != 1 || findings[0].Start != utf8.RuneCountInString(text[:findings[0].ByteStart]) {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestScanHonoursContext(t *testing.T) {
	scanner := mustScanner(t, DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanner.Scan(ctx, "password="+contextValue); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if findings, err := scanner.Scan(context.Background(), ""); err != nil || findings != nil {
		t.Fatalf("empty text: %v, %v", findings, err)
	}
}

func TestErrorsNeverContainValues(t *testing.T) {
	// The only scan error is the context error; construction errors only
	// name configuration (rule ids, thresholds), never scanned text.
	scanner := mustScanner(t, DefaultConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := scanner.Scan(ctx, "password="+contextValue)
	if err == nil || strings.Contains(err.Error(), contextValue) {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveOverlaps(t *testing.T) {
	findings := resolveOverlaps([]rawFinding{
		{source: SourceEntropy, rule: ruleEntropyBase64, start: 2, end: 8},
		{source: SourceGitleaks, rule: "gitleaks:a", start: 0, end: 10},
		{source: SourceGitleaks, rule: "gitleaks:b", start: 0, end: 10},
		{source: SourceKeyword, rule: "keyword:password", start: 20, end: 30},
		{source: SourceKeyword, rule: "keyword:bearer", start: 20, end: 30},
		{source: SourceEntropy, rule: ruleEntropyBase64, start: 25, end: 35},
		{source: SourceGitleaks, rule: "gitleaks:a", start: 0, end: 10},
	})
	got := spans(findings)
	want := []string{"gitleaks:a:0-10", "gitleaks:b:0-10", "keyword:bearer:20-30", "entropy:base64:25-35"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("resolveOverlaps = %v, want %v", got, want)
	}
}

func TestScannerIsSafeForConcurrentUse(t *testing.T) {
	scanner := mustScanner(t, DefaultConfig())
	text := strings.Repeat("password="+contextValue+" ghp_"+newFixtureGen(5).pick(alphaAlnum, 36)+"\n", 20)
	want := describe(scan(t, scanner, text))
	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings, err := scanner.Scan(context.Background(), text)
			if err != nil || describe(findings) != want {
				errs <- "concurrent scan differs"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Fatal(msg)
	}
}

func TestScanIsDeterministic(t *testing.T) {
	scanner := mustScanner(t, DefaultConfig())
	var doc strings.Builder
	for seed, tc := range providerCases() {
		text, _ := tc.build(newFixtureGen(uint64(seed) + 900))
		doc.WriteString(text + "\n")
	}
	first := describe(scan(t, scanner, doc.String()))
	for i := 0; i < 5; i++ {
		if got := describe(scan(t, scanner, doc.String())); got != first {
			t.Fatal("scan results differ between runs")
		}
	}
}
