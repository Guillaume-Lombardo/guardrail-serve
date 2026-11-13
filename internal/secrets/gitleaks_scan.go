package secrets

import (
	"context"
	"fmt"
	"regexp"
	"sort"
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
	lines := lineAllowCache{}
	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(rule.keywords) > 0 && !containsAny(lower, rule.keywords) {
			continue
		}
		for n, index := range rule.regex.FindAllStringIndex(text, -1) {
			if n%ctxCheckInterval == ctxCheckInterval-1 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
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
			found, ok := evaluateGitleaksMatch(view, rule, global, lines, start, end)
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

// ctxCheckInterval is how many matches, assignments or candidates are
// evaluated between two context checks.
const ctxCheckInterval = 256

// ctxPoll checks the context every ctxCheckInterval steps of a scan phase.
type ctxPoll struct {
	ctx context.Context
	n   int
}

func (p *ctxPoll) check() error {
	p.n++
	if p.n%ctxCheckInterval != 0 {
		return nil
	}
	return p.ctx.Err()
}

// lineAllowCache memoizes the line-target regexes of an allowlist per line:
// many matches on one long line must not rescan the line each time.
type lineAllowCache map[lineAllowKey]bool

type lineAllowKey struct {
	allowlist  *gitleaksAllowlist
	start, end int
}

func evaluateGitleaksMatch(view *textView, rule gitleaksRule, global []gitleaksAllowlist, lines lineAllowCache, start, end int) (gitleaksMatch, bool) {
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
		ruleGeneric: strings.Contains(strings.ToLower(rule.id), "generic"),
	}
	lineStart, lineEnd := view.lineSpan(start, end)
	line := lineRef{text: view.text, start: lineStart, end: lineEnd, cache: lines}
	if allowlisted(global, found, line) || allowlisted(rule.allowlists, found, line) {
		return gitleaksMatch{}, false
	}
	return found, true
}

// lineRef is the line of a match, with the per-scan cache of line-target
// allowlist results.
type lineRef struct {
	text       string
	start, end int
	cache      lineAllowCache
}

func (line lineRef) matches(allowlist *gitleaksAllowlist) bool {
	key := lineAllowKey{allowlist: allowlist, start: line.start, end: line.end}
	allowed, ok := line.cache[key]
	if !ok {
		target := line.text[line.start:line.end]
		allowed = target != "" && anyRegexMatch(allowlist.regexes, target)
		line.cache[key] = allowed
	}
	return allowed
}

// allowlisted mirrors detect.checkFindingAllowed with no commit and no path:
// commit and path criteria never match.
func allowlisted(allowlists []gitleaksAllowlist, found gitleaksMatch, line lineRef) bool {
	for i := range allowlists {
		allowlist := &allowlists[i]
		if allowlist.and && (allowlist.hasCommits || allowlist.hasPaths) {
			continue // a commit or path criterion can never hold
		}
		regexAllowed := func() bool {
			if len(allowlist.regexes) == 0 {
				return false
			}
			switch allowlist.target {
			case targetMatch:
				return found.match != "" && anyRegexMatch(allowlist.regexes, found.match)
			case targetLine:
				return line.matches(allowlist)
			default:
				return found.secret != "" && anyRegexMatch(allowlist.regexes, found.secret)
			}
		}
		stopword := func() bool {
			return found.secret != "" && containsAny(strings.ToLower(found.secret), allowlist.stopwords)
		}
		if allowlist.and {
			if (len(allowlist.regexes) == 0 || regexAllowed()) && (len(allowlist.stopwords) == 0 || stopword()) {
				return true
			}
			continue
		}
		if regexAllowed() || stopword() {
			return true
		}
	}
	return false
}

// filterGeneric mirrors detect.filter: a finding of a "generic" rule is
// dropped when a non-generic rule found a secret containing it on the same
// line. Upstream compares secret strings; here the non-generic secret span
// must contain the generic one, which is the same finding in every case
// that matters and keeps the filter O(n log n). A generic finding equal to
// a non-generic secret found elsewhere on the line is kept, which only
// masks more.
func filterGeneric(matches []gitleaksMatch) []gitleaksMatch {
	var specific []gitleaksMatch
	for _, m := range matches {
		if !m.ruleGeneric {
			specific = append(specific, m)
		}
	}
	if len(specific) == len(matches) {
		return matches
	}
	sort.Slice(specific, func(i, j int) bool { return specific[i].start < specific[j].start })
	// maxEnd[i] is the largest end among specific[:i+1].
	maxEnd := make([]int, len(specific))
	for i, m := range specific {
		maxEnd[i] = m.end
		if i > 0 {
			maxEnd[i] = max(maxEnd[i], maxEnd[i-1])
		}
	}
	kept := matches[:0:0]
	for _, candidate := range matches {
		if candidate.ruleGeneric {
			i := sort.Search(len(specific), func(i int) bool { return specific[i].start > candidate.start }) - 1
			if i >= 0 && maxEnd[i] >= candidate.end {
				continue
			}
		}
		kept = append(kept, candidate)
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
