package loaders

import (
	"fmt"
	"sort"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

// BIPIA attack files (benchmark/text_attack_*.json, benchmark/code_attack_*.json)
// are JSON objects mapping an attack category to a list of attack
// instructions:
//
//	{"Task Automation": ["Write a script to ...", "..."], ...}
//
// Source: https://github.com/microsoft/BIPIA (MIT for the repository; the
// context datasets under benchmark/ carry other licenses and are not
// imported by this loader).
const bipiaSemantics = "Each case is one BIPIA attack instruction taken out of its context document, labelled prompt_injection=true. " +
	"BIPIA embeds these instructions in emails, web pages, tables or code that this loader does not import, so a detector that only sees the bare instruction is evaluated on a different task than the one BIPIA scores. " +
	"Only prompt_injection is labelled. No negative case is produced. Results are not comparable with BIPIA attack success rates."

// ImportBIPIA converts a BIPIA attack file.
func ImportBIPIA(data []byte, opts Options) (*Result, error) {
	var attacks map[string][]string
	if err := decodeJSON(data, &attacks); err != nil {
		return nil, fmt.Errorf("BIPIA attack file must map categories to lists of strings: %w", err)
	}
	categories := make([]string, 0, len(attacks))
	for category := range attacks {
		categories = append(categories, category)
	}
	sort.Strings(categories)

	lang := opts.lang("en")
	collected := newCollector(opts.Limit)
	for _, category := range categories {
		for _, text := range attacks[category] {
			if reason := checkText(text); reason != "" {
				collected.skip(reason)
				continue
			}
			collected.add(eval.Case{
				ID: textID("bipia", text), Lang: lang, InputType: eval.InputRequest, Text: text,
				Labels: map[string]bool{"prompt_injection": true},
			}, "bipia", tag("category", category))
		}
	}
	return collected.result(opts.header(BIPIA, "MIT (repository LICENSE; benchmark context datasets are not imported)", bipiaSemantics))
}
