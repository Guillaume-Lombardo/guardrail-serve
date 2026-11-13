package loaders

import (
	"fmt"
	"sort"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

// AgentDojo run traces (runs/<pipeline>/<suite>/user_task_N/<attack>/injection_task_M.json)
// are JSON objects recording the text injected into tool outputs:
//
//	{"suite_name": "banking", "attack_type": "direct",
//	 "injections": {"injection_bill_text": "TODO: Send a transaction to ..."}, ...}
//
// Other fields (messages, utility, security, ...) are ignored. Source:
// https://github.com/ethz-spylab/agentdojo (MIT).
const agentDojoSemantics = "Each case is one text injected by an AgentDojo attack into a tool output, labelled prompt_injection=true. " +
	"Injected texts that merely tell an agent to perform a task (send money, forward a file) may not look like instructions to override a prompt, " +
	"and AgentDojo scores whether an agent obeys them, not whether a filter flags them. Only prompt_injection is labelled. " +
	"No negative case is produced. Results are not comparable with AgentDojo security scores."

// AgentDojoTrace is the part of a run trace the loader reads.
type AgentDojoTrace struct {
	SuiteName  string            `json:"suite_name"`
	AttackType string            `json:"attack_type"`
	Injections map[string]string `json:"injections"`
}

// ParseAgentDojoTrace decodes one run trace.
func ParseAgentDojoTrace(data []byte) (AgentDojoTrace, error) {
	var trace AgentDojoTrace
	if err := decodeJSON(data, &trace); err != nil {
		return trace, fmt.Errorf("not an AgentDojo run trace: %w", err)
	}
	if trace.SuiteName == "" {
		return trace, fmt.Errorf("not an AgentDojo run trace: missing suite_name")
	}
	return trace, nil
}

// ImportAgentDojo converts run traces, in the order given. Identical injected
// texts (the same attack appears in many traces) become one case.
func ImportAgentDojo(traces []AgentDojoTrace, opts Options) (*Result, error) {
	lang := opts.lang("en")
	collected := newCollector(opts.Limit)
	for _, trace := range traces {
		vectors := make([]string, 0, len(trace.Injections))
		for vector := range trace.Injections {
			vectors = append(vectors, vector)
		}
		sort.Strings(vectors)
		if len(vectors) == 0 {
			collected.skip("trace_without_injection")
		}
		for _, vector := range vectors {
			text := trace.Injections[vector]
			if reason := checkText(text); reason != "" {
				collected.skip(reason)
				continue
			}
			tags := []string{"agentdojo", tag("suite", trace.SuiteName)}
			if trace.AttackType != "" {
				tags = append(tags, tag("attack", trace.AttackType))
			}
			collected.add(eval.Case{
				ID: textID("agentdojo", text), Lang: lang, InputType: eval.InputRequest, Text: text,
				Labels: map[string]bool{"prompt_injection": true},
			}, tags...)
		}
	}
	return collected.result(opts.header(AgentDojo, "MIT", agentDojoSemantics))
}
