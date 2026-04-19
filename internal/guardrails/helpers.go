package guardrails

import (
	"regexp"
	"sort"
	"strings"

	"github.com/g1lom/guardrail-serve/internal/domain"
)

type NamedPattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

type Finding struct {
	Start int
	End   int
}

func compilePatterns(items []NamedPattern) ([]compiledPattern, error) {
	output := make([]compiledPattern, 0, len(items))
	for _, item := range items {
		re, err := regexp.Compile(item.Regex)
		if err != nil {
			return nil, err
		}
		output = append(output, compiledPattern{Name: item.Name, Regex: re})
	}
	return output, nil
}

type compiledPattern struct {
	Name  string
	Regex *regexp.Regexp
}

func deduplicateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Start == findings[j].Start {
			return findings[i].End < findings[j].End
		}
		return findings[i].Start < findings[j].Start
	})

	result := make([]Finding, 0, len(findings))
	var prev Finding
	for index, item := range findings {
		if index == 0 || item.Start != prev.Start || item.End != prev.End {
			result = append(result, item)
			prev = item
		}
	}
	return result
}

func redactText(text, mask string, findings []Finding) (string, bool) {
	if len(findings) == 0 {
		return text, false
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Start == findings[j].Start {
			return findings[i].End < findings[j].End
		}
		return findings[i].Start < findings[j].Start
	})

	merged := []Finding{findings[0]}
	for _, item := range findings[1:] {
		last := &merged[len(merged)-1]
		if item.Start > last.End {
			merged = append(merged, item)
			continue
		}
		if item.End > last.End {
			last.End = item.End
		}
	}

	var builder strings.Builder
	cursor := 0
	for _, item := range merged {
		builder.WriteString(text[cursor:item.Start])
		builder.WriteString(mask)
		cursor = item.End
	}
	builder.WriteString(text[cursor:])
	return builder.String(), true
}

func responseFromResult(name string, original []string, result domain.Result) domain.Response {
	texts := result.Texts
	if !result.Modified {
		texts = original
	}
	return domain.Response{
		Decision: result.Decision,
		Texts:    texts,
		Metadata: map[string]any{"guardrail": name},
		Reason:   result.Reason,
	}
}

func stringPtr(value string) *string {
	return &value
}
