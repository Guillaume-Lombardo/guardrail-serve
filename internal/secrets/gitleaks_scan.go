package secrets

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var defaultGitleaksRules = sync.OnceValues(func() (*gitleaksRuleSet, error) {
	body, err := gitleaksBody(gitleaksRulesFile)
	if err != nil {
		return nil, err
	}
	return loadGitleaksRules(body)
})

// active returns the rules left after disabling ids.
func (set *gitleaksRuleSet) active(disabled []string) ([]gitleaksRule, error) {
	skip := map[string]bool{}
	for _, id := range disabled {
		if _, ok := set.byID[id]; !ok {
			if set.isExcluded(id) {
				return nil, fmt.Errorf("gitleaks rule %q is excluded and cannot be disabled", id)
			}
			return nil, fmt.Errorf("unknown gitleaks rule %q", id)
		}
		skip[id] = true
	}
	rules := make([]gitleaksRule, 0, len(set.rules)-len(skip))
	for _, rule := range set.rules {
		if !skip[rule.id] {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

// gitleaksMatch is a candidate finding with the context the allowlists and
// the generic-rule filter need.
type gitleaksMatch struct {
	rule        string
	start, end  int // secret span, bytes
	match       string
	secret      string
	line        int
	ruleGeneric bool
}

// scanGitleaks reproduces gitleaks Detector.DetectString for one fragment
// without file path or commit (detect/detect.go at the pinned commit):
// keyword prefilter, regex match with surrounding newlines trimmed, secret
// group selection, entropy threshold, global then rule allowlists, then the
// "generic" rule precedence filter. Inline "gitleaks:allow" comments and
// decoding passes are intentionally not supported (see the package README).
func scanGitleaks(ctx context.Context, view *textView, rules []gitleaksRule, global []gitleaksAllowlist) ([]rawFinding, error) {
	text := view.text
	lower := view.lowered()
	var matches []gitleaksMatch
	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(rule.keywords) > 0 && !containsAny(lower, rule.keywords) {
			continue
		}
		for _, index := range rule.regex.FindAllStringIndex(text, -1) {
			start, end := index[0], index[1]
			for start < end && text[start] == '\n' {
				start++
			}
			for end > start && text[end-1] == '\n' {
				end--
			}
			if start == end {
				continue
			}
			found, ok := evaluateGitleaksMatch(view, rule, global, start, end)
			if ok {
				matches = append(matches, found)
			}
		}
	}
	matches = filterGeneric(matches)
	findings := make([]rawFinding, 0, len(matches))
	for _, found := range matches {
		findings = append(findings, rawFinding{
			source: SourceGitleaks,
			rule:   gitleaksRulePrefix + found.rule,
			kind:   TypeSecret,
			start:  found.start,
			end:    found.end,
		})
	}
	return findings, nil
}

func evaluateGitleaksMatch(view *textView, rule gitleaksRule, global []gitleaksAllowlist, start, end int) (gitleaksMatch, bool) {
	match := view.text[start:end]
	secretStart, secretEnd := start, end
	// Like gitleaks, the secret groups come from matching the regex again
	// on the trimmed match.
	groups := rule.regex.FindStringSubmatchIndex(match)
	emptySecret := false
	if len(groups) >= 4 {
		if rule.secretGroup > 0 {
			gs, ge := groups[2*rule.secretGroup], groups[2*rule.secretGroup+1]
			if gs >= 0 && ge > gs {
				secretStart, secretEnd = start+gs, start+ge
			} else {
				emptySecret = true
			}
		} else {
			for group := 1; 2*group+1 < len(groups); group++ {
				gs, ge := groups[2*group], groups[2*group+1]
				if gs >= 0 && ge > gs {
					secretStart, secretEnd = start+gs, start+ge
					break
				}
			}
		}
	}
	secret := view.text[secretStart:secretEnd]
	if emptySecret {
		// gitleaks reports an empty secret here; an empty secret has zero
		// entropy and cannot be masked, so the whole match is reported
		// unless the rule requires entropy.
		if rule.entropy != 0 {
			return gitleaksMatch{}, false
		}
		secret = ""
	} else if rule.entropy != 0 && shannonEntropy(secret) <= rule.entropy {
		return gitleaksMatch{}, false
	}
	found := gitleaksMatch{
		rule:        rule.id,
		start:       secretStart,
		end:         secretEnd,
		match:       match,
		secret:      secret,
		line:        view.lineNumber(start),
		ruleGeneric: strings.Contains(strings.ToLower(rule.id), "generic"),
	}
	lineStart, lineEnd := view.lineSpan(start, end)
	lineText := view.text[lineStart:lineEnd]
	if allowlisted(global, found, lineText) || allowlisted(rule.allowlists, found, lineText) {
		return gitleaksMatch{}, false
	}
	return found, true
}

// allowlisted mirrors detect.checkFindingAllowed with no commit and no path:
// commit and path criteria never match.
func allowlisted(allowlists []gitleaksAllowlist, found gitleaksMatch, line string) bool {
	for _, allowlist := range allowlists {
		target := found.secret
		switch allowlist.target {
		case targetMatch:
			target = found.match
		case targetLine:
			target = line
		}
		regexAllowed := target != "" && anyRegexMatch(allowlist.regexes, target)
		stopword := found.secret != "" && containsAny(strings.ToLower(found.secret), allowlist.stopwords)
		if allowlist.and {
			checks := true
			if allowlist.hasCommits || allowlist.hasPaths {
				checks = false
			}
			if len(allowlist.regexes) > 0 {
				checks = checks && regexAllowed
			}
			if len(allowlist.stopwords) > 0 {
				checks = checks && stopword
			}
			if checks {
				return true
			}
			continue
		}
		if regexAllowed || stopword {
			return true
		}
	}
	return false
}

// filterGeneric mirrors detect.filter: a finding of a "generic" rule is
// dropped when a non-generic rule found a secret containing it on the same
// line.
func filterGeneric(matches []gitleaksMatch) []gitleaksMatch {
	kept := matches[:0:0]
	for _, candidate := range matches {
		dropped := false
		if candidate.ruleGeneric {
			for _, other := range matches {
				if other.line == candidate.line && other.rule != candidate.rule && !other.ruleGeneric &&
					strings.Contains(other.secret, candidate.secret) {
					dropped = true
					break
				}
			}
		}
		if !dropped {
			kept = append(kept, candidate)
		}
	}
	return kept
}

func anyRegexMatch(regexes []*regexp.Regexp, target string) bool {
	for _, re := range regexes {
		if re.MatchString(target) {
			return true
		}
	}
	return false
}

func containsAny(s string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
