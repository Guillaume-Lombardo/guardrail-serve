package loaders

import (
	"fmt"
	"strings"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

// Presidio evaluation data (microsoft/presidio-research, MIT) is a JSON array
// of synthetic records:
//
//	[{"full_text": "Call me at ...", "spans": [{"entity_type": "EMAIL_ADDRESS",
//	  "entity_value": "...", "start_position": 3, "end_position": 9}], ...}]
//
// Files used by this repository's documentation: data/synth_dataset_v2.json
// and tests/data/generated_small.json.
const presidioSemantics = "Each case is one synthetic Presidio sentence. detect_pii=true when the record has at least one span of a mapped entity type (mapped here: %s); " +
	"detect_pii=false only when the record has no span at all. Records whose only spans are other entity types (PERSON, LOCATION, PHONE_NUMBER, US_SSN, ...) are skipped because detect_pii does not target them, " +
	"so they are neither positive nor negative. Presidio PHONE_NUMBER values are mostly not French numbers, the only phone format detect_pii targets, so PHONE_NUMBER is not mapped unless requested. " +
	"IP_ADDRESS may include IPv6, which detect_pii does not target. Labels are record-level presence, not span-level, and are not equivalent to Presidio's span-level scores."

// DefaultPresidioEntities are the Presidio entity types mapped to detect_pii.
var DefaultPresidioEntities = []string{"EMAIL_ADDRESS", "CREDIT_CARD", "IP_ADDRESS", "IBAN_CODE"}

type presidioRecord struct {
	FullText *string `json:"full_text"`
	Spans    *[]struct {
		EntityType string `json:"entity_type"`
	} `json:"spans"`
}

// ImportPresidio converts a Presidio evaluation dataset.
func ImportPresidio(data []byte, opts Options) (*Result, error) {
	var records []presidioRecord
	if err := decodeJSON(data, &records); err != nil {
		return nil, fmt.Errorf("Presidio dataset must be a JSON array of records: %w", err)
	}
	mapped := map[string]bool{}
	entities := opts.Entities
	if len(entities) == 0 {
		entities = DefaultPresidioEntities
	}
	for _, entity := range entities {
		mapped[strings.TrimSpace(entity)] = true
	}

	lang := opts.lang("en")
	collected := newCollector(opts.Limit)
	for index, record := range records {
		if record.FullText == nil || record.Spans == nil {
			return nil, fmt.Errorf("record %d lacks full_text or spans", index)
		}
		text := *record.FullText
		if reason := checkText(text); reason != "" {
			collected.skip(reason)
			continue
		}
		covered, other := map[string]bool{}, false
		for _, span := range *record.Spans {
			if mapped[span.EntityType] {
				covered[span.EntityType] = true
			} else {
				other = true
			}
		}
		item := eval.Case{ID: textID("presidio", text), Lang: lang, InputType: eval.InputRequest, Text: text}
		tags := []string{"presidio"}
		switch {
		case len(covered) > 0:
			item.Labels = map[string]bool{"detect_pii": true}
			for _, entity := range sortedSet(covered) {
				tags = append(tags, tag("entity", entity))
			}
		case !other:
			item.Labels = map[string]bool{"detect_pii": false}
			tags = append(tags, "no-entities")
		default:
			collected.skip("uncovered_entities_only")
			continue
		}
		if len(tags) > 16 {
			tags = tags[:16]
		}
		collected.add(item, tags...)
	}
	return collected.result(opts.header(Presidio, "MIT (microsoft/presidio-research)", fmt.Sprintf(presidioSemantics, strings.Join(sortedSet(mapped), ", "))))
}
