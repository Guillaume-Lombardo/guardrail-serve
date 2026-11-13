package secrets

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Provenance of the vendored gitleaks default rules (see rules/gitleaks.toml).
const (
	GitleaksVersion        = "v8.30.1"
	GitleaksCommit         = "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
	GitleaksUpstreamSHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
	gitleaksRulePrefix     = "gitleaks:"
	gitleaksBodyMarker     = "# ---- upstream content below ----\n"
)

//go:embed rules/gitleaks.toml
var gitleaksRulesFile string

// RuleExclusion records a vendored rule that cannot apply to free text.
type RuleExclusion struct {
	ID     string
	Reason string
}

type regexTarget int

const (
	targetSecret regexTarget = iota
	targetMatch
	targetLine
)

// gitleaksAllowlist mirrors config.Allowlist. Commit and path criteria are
// kept only as flags: scanned texts have neither, so they never match, exactly
// like gitleaks scanning a fragment without FilePath or CommitSHA.
type gitleaksAllowlist struct {
	and        bool
	target     regexTarget
	regexes    []*regexp.Regexp
	stopwords  []string
	hasCommits bool
	hasPaths   bool
}

type gitleaksRule struct {
	id          string
	regex       *regexp.Regexp
	secretGroup int
	entropy     float64
	keywords    []string
	allowlists  []gitleaksAllowlist
}

type gitleaksRuleSet struct {
	rules    []gitleaksRule
	global   []gitleaksAllowlist
	excluded []RuleExclusion
	byID     map[string]int
	// lastExcluded is true while the most recent [[rules]] table was
	// excluded, so its [[rules.allowlists]] are dropped with it.
	lastExcluded bool
}

var (
	ruleKeys      = setOf("id", "description", "regex", "path", "entropy", "secretGroup", "keywords", "tags")
	allowlistKeys = setOf("description", "condition", "commits", "paths", "regexTarget", "regexes", "stopwords")
	rootKeys      = setOf("title", "minVersion")
)

func setOf(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

// gitleaksBody returns the upstream part of the vendored rules file.
func gitleaksBody(file string) (string, error) {
	_, body, ok := strings.Cut(file, gitleaksBodyMarker)
	if !ok {
		return "", fmt.Errorf("rules file has no upstream content marker")
	}
	return body, nil
}

// loadGitleaksRules parses and compiles a gitleaks configuration. Every regex
// is compiled with Go's RE2 engine at load time, so an incompatible construct
// fails construction instead of a scan.
func loadGitleaksRules(src string) (*gitleaksRuleSet, error) {
	tables, err := parseTOMLSubset(src)
	if err != nil {
		return nil, err
	}
	set := &gitleaksRuleSet{byID: map[string]int{}}
	for _, table := range tables {
		switch table.kind {
		case tomlRoot:
			if err := checkKeys(table, rootKeys, "root"); err != nil {
				return nil, err
			}
		case tomlGlobalAllowlist, tomlGlobalAllowlists:
			allowlist, err := compileAllowlist(table)
			if err != nil {
				return nil, fmt.Errorf("global allowlist (line %d): %w", table.line, err)
			}
			set.global = append(set.global, allowlist)
		case tomlRule:
			if err := set.addRule(table); err != nil {
				return nil, err
			}
		case tomlRuleAllowlist:
			if err := set.addRuleAllowlist(table); err != nil {
				return nil, err
			}
		}
	}
	if len(set.rules) == 0 {
		return nil, fmt.Errorf("rules file defines no applicable rule")
	}
	return set, nil
}

func checkKeys(table tomlTable, allowed map[string]bool, scope string) error {
	keys := make([]string, 0, len(table.values))
	for key := range table.values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !allowed[key] {
			return fmt.Errorf("%s (line %d): unsupported key %q", scope, table.line, key)
		}
	}
	return nil
}

func stringField(table tomlTable, key string) (string, bool, error) {
	value, ok := table.values[key]
	if !ok {
		return "", false, nil
	}
	if value.kind != tomlString {
		return "", false, fmt.Errorf("line %d: %s must be a string", value.line, key)
	}
	return value.str, true, nil
}

func stringsField(table tomlTable, key string) ([]string, error) {
	value, ok := table.values[key]
	if !ok {
		return nil, nil
	}
	if value.kind != tomlStringArray {
		return nil, fmt.Errorf("line %d: %s must be an array of strings", value.line, key)
	}
	return value.strs, nil
}

func compileRegexes(patterns []string, scope string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for index, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: not RE2-compatible: %w", scope, index, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

func (set *gitleaksRuleSet) addRule(table tomlTable) error {
	id, _, err := stringField(table, "id")
	if err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("rule (line %d): id is missing or empty", table.line)
	}
	scope := "rule " + id
	if err := checkKeys(table, ruleKeys, scope); err != nil {
		return err
	}
	if _, dup := set.byID[id]; dup || set.isExcluded(id) {
		return fmt.Errorf("%s: duplicate rule id", scope)
	}
	if _, err := stringsField(table, "tags"); err != nil {
		return fmt.Errorf("%s: %w", scope, err)
	}
	if _, _, err := stringField(table, "description"); err != nil {
		return fmt.Errorf("%s: %w", scope, err)
	}
	pattern, hasRegex, err := stringField(table, "regex")
	if err != nil {
		return fmt.Errorf("%s: %w", scope, err)
	}
	path, hasPath, err := stringField(table, "path")
	if err != nil {
		return fmt.Errorf("%s: %w", scope, err)
	}
	if !hasRegex && !hasPath {
		return fmt.Errorf("%s: both regex and path are empty", scope)
	}
	if hasPath {
		pathRe, err := regexp.Compile(path)
		if err != nil {
			return fmt.Errorf("%s: path not RE2-compatible: %w", scope, err)
		}
		// gitleaks only evaluates the regex of a path-scoped rule when the
		// fragment path matches. Texts have an empty path.
		if !hasRegex {
			set.exclude(id, "path-only rule: matches file names, not content")
			return nil
		}
		if !pathRe.MatchString("") {
			set.exclude(id, "path-scoped rule: requires a matching file path, which free text has not")
			return nil
		}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("%s: regex not RE2-compatible: %w", scope, err)
	}
	rule := gitleaksRule{id: id, regex: re}
	if value, ok := table.values["secretGroup"]; ok {
		if value.kind != tomlInteger || value.integer < 0 {
			return fmt.Errorf("%s: secretGroup must be a non-negative integer", scope)
		}
		if int(value.integer) > re.NumSubexp() {
			return fmt.Errorf("%s: secretGroup %d exceeds %d capture groups", scope, value.integer, re.NumSubexp())
		}
		rule.secretGroup = int(value.integer)
	}
	if value, ok := table.values["entropy"]; ok {
		if (value.kind != tomlFloat && value.kind != tomlInteger) || value.num < 0 {
			return fmt.Errorf("%s: entropy must be a non-negative number", scope)
		}
		rule.entropy = value.num
	}
	keywords, err := stringsField(table, "keywords")
	if err != nil {
		return fmt.Errorf("%s: %w", scope, err)
	}
	for _, keyword := range keywords {
		if keyword == "" {
			return fmt.Errorf("%s: empty keyword", scope)
		}
		rule.keywords = append(rule.keywords, strings.ToLower(keyword))
	}
	set.byID[id] = len(set.rules)
	set.rules = append(set.rules, rule)
	set.lastExcluded = false
	return nil
}

func (set *gitleaksRuleSet) exclude(id, reason string) {
	set.excluded = append(set.excluded, RuleExclusion{ID: id, Reason: reason})
	set.lastExcluded = true
}

func (set *gitleaksRuleSet) isExcluded(id string) bool {
	for _, exclusion := range set.excluded {
		if exclusion.ID == id {
			return true
		}
	}
	return false
}

// addRuleAllowlist attaches [[rules.allowlists]] to the latest rule table. An
// allowlist that follows an excluded rule is validated and then dropped.
func (set *gitleaksRuleSet) addRuleAllowlist(table tomlTable) error {
	allowlist, err := compileAllowlist(table)
	if err != nil {
		return fmt.Errorf("rule allowlist (line %d): %w", table.line, err)
	}
	if set.lastExcluded {
		return nil
	}
	last := &set.rules[len(set.rules)-1]
	last.allowlists = append(last.allowlists, allowlist)
	return nil
}

func compileAllowlist(table tomlTable) (gitleaksAllowlist, error) {
	if err := checkKeys(table, allowlistKeys, "allowlist"); err != nil {
		return gitleaksAllowlist{}, err
	}
	var allowlist gitleaksAllowlist
	if _, _, err := stringField(table, "description"); err != nil {
		return allowlist, err
	}
	condition, _, err := stringField(table, "condition")
	if err != nil {
		return allowlist, err
	}
	switch strings.ToUpper(condition) {
	case "AND", "&&":
		allowlist.and = true
	case "", "OR", "||":
	default:
		return allowlist, fmt.Errorf("unknown condition %q (expected AND or OR)", condition)
	}
	target, _, err := stringField(table, "regexTarget")
	if err != nil {
		return allowlist, err
	}
	switch target {
	case "", "secret":
		allowlist.target = targetSecret
	case "match":
		allowlist.target = targetMatch
	case "line":
		allowlist.target = targetLine
	default:
		return allowlist, fmt.Errorf("unknown regexTarget %q (expected secret, match or line)", target)
	}
	commits, err := stringsField(table, "commits")
	if err != nil {
		return allowlist, err
	}
	paths, err := stringsField(table, "paths")
	if err != nil {
		return allowlist, err
	}
	if _, err := compileRegexes(paths, "paths"); err != nil {
		return allowlist, err
	}
	patterns, err := stringsField(table, "regexes")
	if err != nil {
		return allowlist, err
	}
	if allowlist.regexes, err = compileRegexes(patterns, "regexes"); err != nil {
		return allowlist, err
	}
	stopwords, err := stringsField(table, "stopwords")
	if err != nil {
		return allowlist, err
	}
	seen := map[string]bool{}
	for _, word := range stopwords {
		word = strings.ToLower(word)
		if word == "" || seen[word] {
			continue
		}
		seen[word] = true
		allowlist.stopwords = append(allowlist.stopwords, word)
	}
	allowlist.hasCommits = len(commits) > 0
	allowlist.hasPaths = len(paths) > 0
	if !allowlist.hasCommits && !allowlist.hasPaths && len(allowlist.regexes) == 0 && len(allowlist.stopwords) == 0 {
		return allowlist, fmt.Errorf("must contain at least one check for commits, paths, regexes or stopwords")
	}
	return allowlist, nil
}
