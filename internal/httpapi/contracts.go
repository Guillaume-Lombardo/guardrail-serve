package httpapi

import (
	"bytes"
	"encoding/json"

	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/policy"
)

type scanRequestBody struct {
	Texts              []string         `json:"texts,omitempty" doc:"Text items to scan." minItems:"1"`
	Images             []string         `json:"images,omitempty" doc:"Currently unsupported placeholder for future multimodal support."`
	Tools              []map[string]any `json:"tools,omitempty" doc:"Currently unsupported placeholder for future tool-aware evaluation."`
	ToolCalls          []map[string]any `json:"tool_calls,omitempty" doc:"Currently unsupported placeholder for future tool-call evaluation."`
	StructuredMessages []map[string]any `json:"structured_messages,omitempty" doc:"Currently unsupported placeholder for future structured chat payloads."`
	RequestData        map[string]any   `json:"request_data,omitempty" doc:"Opaque request metadata; accepted but not evaluated."`
	InputType          domain.Scope     `json:"input_type,omitempty" doc:"Guardrail execution scope: request or response." enum:"request,response"`
}

func (b *scanRequestBody) UnmarshalJSON(data []byte) error {
	type alias scanRequestBody

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	var payload alias
	if err := decoder.Decode(&payload); err != nil {
		return errInvalidJSON
	}

	*b = scanRequestBody(payload)
	b.normalize()
	return nil
}

func (b *scanRequestBody) normalize() {
	if b.Texts == nil {
		b.Texts = []string{}
	}
	if b.Images == nil {
		b.Images = []string{}
	}
	if b.Tools == nil {
		b.Tools = []map[string]any{}
	}
	if b.ToolCalls == nil {
		b.ToolCalls = []map[string]any{}
	}
	if b.StructuredMessages == nil {
		b.StructuredMessages = []map[string]any{}
	}
	if b.RequestData == nil {
		b.RequestData = map[string]any{}
	}
	if b.InputType == "" {
		b.InputType = domain.ScopeRequest
	}
}

func (b scanRequestBody) toDomain() domain.Request {
	return domain.Request{
		Texts:              b.Texts,
		Images:             b.Images,
		Tools:              b.Tools,
		ToolCalls:          b.ToolCalls,
		StructuredMessages: b.StructuredMessages,
		RequestData:        b.RequestData,
		InputType:          b.InputType,
	}
}

type scanRequestInput struct {
	Body scanRequestBody
}

type scanResponseBody struct {
	Decision domain.Decision `json:"decision" doc:"Guardrail decision outcome." enum:"NONE,BLOCKED,GUARDRAIL_INTERVENED"`
	Texts    []string        `json:"texts" doc:"Returned or redacted text items."`
	Metadata map[string]any  `json:"metadata" doc:"Guardrail execution metadata."`
	Reason   *string         `json:"reason,omitempty" doc:"Optional blocking reason."`
}

type scanResponseOutput struct {
	Body scanResponseBody
}

func newScanResponseOutput(route scanRoute, evaluation policy.Evaluation) *scanResponseOutput {
	metadata := map[string]any{"guardrail": route.guardrail}
	if evaluation.LimitExceeded {
		metadata["guardrail"] = limitsGuardrail
	} else if route.reportRules != nil {
		metadata["matched_rules"] = matchedRules(evaluation, route.reportRules)
	}
	return &scanResponseOutput{
		Body: scanResponseBody{
			Decision: evaluation.Decision,
			Texts:    evaluation.Texts,
			Metadata: metadata,
			Reason:   evaluation.Reason,
		},
	}
}

// matchedRules keeps the historical /scan/prompt-injection order: texts in
// request order, rules in configuration order, each rule listed once.
func matchedRules(evaluation policy.Evaluation, order []string) []string {
	byText := make([]map[string]bool, len(evaluation.Texts))
	for _, finding := range evaluation.Findings {
		if byText[finding.TextIndex] == nil {
			byText[finding.TextIndex] = map[string]bool{}
		}
		byText[finding.TextIndex][finding.Rule] = true
	}
	matched := []string{}
	seen := map[string]bool{}
	for _, rules := range byText {
		for _, rule := range order {
			if rules[rule] && !seen[rule] {
				seen[rule] = true
				matched = append(matched, rule)
			}
		}
	}
	return matched
}

// policyRequestBody is the strict native policy contract (API version 1).
type policyRequestBody struct {
	Texts       []string       `json:"texts" doc:"Text items to evaluate, in order." minItems:"1"`
	InputType   domain.Scope   `json:"input_type,omitempty" doc:"request selects the input stage, response the output stage. Defaults to request." enum:"request,response"`
	RequestData map[string]any `json:"request_data,omitempty" doc:"Opaque request metadata; accepted but not evaluated."`
}

type policyRequestInput struct {
	Policy string `path:"policy" doc:"Name of a configured policy."`
	Body   policyRequestBody
}

type findingBody struct {
	TextIndex int           `json:"text_index" doc:"Index of the request text item containing the finding." minimum:"0"`
	Detector  string        `json:"detector" doc:"Detector that produced the finding."`
	Type      string        `json:"type" doc:"Finding category, also used by typed masks." example:"EMAIL"`
	Rule      string        `json:"rule" doc:"Detector rule name."`
	Start     int           `json:"start" doc:"Inclusive Unicode code point (rune) offset in the original text item." minimum:"0"`
	End       int           `json:"end" doc:"Exclusive Unicode code point (rune) offset in the original text item." minimum:"1"`
	Score     *float64      `json:"score,omitempty" doc:"Detector confidence when the detector provides one."`
	Action    domain.Action `json:"action" doc:"Action configured for the detector step." enum:"block,mask,annotate"`
}

type policyResponseBody struct {
	Policy         string          `json:"policy" doc:"Evaluated policy name."`
	Mode           domain.Mode     `json:"mode" doc:"enforce applies actions; detect only reports them." enum:"enforce,detect"`
	Stage          domain.Stage    `json:"stage" doc:"Evaluated stage." enum:"input,output"`
	Decision       domain.Decision `json:"decision" doc:"Applied decision. Always NONE in detect mode unless payload limits blocked." enum:"NONE,BLOCKED,GUARDRAIL_INTERVENED"`
	PolicyDecision domain.Decision `json:"policy_decision" doc:"Decision the policy produces when enforced." enum:"NONE,BLOCKED,GUARDRAIL_INTERVENED"`
	Texts          []string        `json:"texts" doc:"Text items aligned one to one with the request; masked only when decision is GUARDRAIL_INTERVENED."`
	Findings       []findingBody   `json:"findings" doc:"Findings sorted by text_index, start, end, chain position and rule. Never contains matched values."`
	Reason         *string         `json:"reason,omitempty" doc:"Value-free explanation when policy_decision is BLOCKED."`
}

type policyResponseOutput struct {
	Body policyResponseBody
}

func newPolicyResponseOutput(evaluation policy.Evaluation) *policyResponseOutput {
	findings := make([]findingBody, len(evaluation.Findings))
	for i, finding := range evaluation.Findings {
		findings[i] = findingBody{
			TextIndex: finding.TextIndex, Detector: finding.Detector, Type: finding.Type, Rule: finding.Rule,
			Start: finding.Start, End: finding.End, Score: finding.Score, Action: finding.Action,
		}
	}
	return &policyResponseOutput{Body: policyResponseBody{
		Policy: evaluation.Policy, Mode: evaluation.Mode, Stage: evaluation.Stage,
		Decision: evaluation.Decision, PolicyDecision: evaluation.PolicyDecision,
		Texts: evaluation.Texts, Findings: findings, Reason: evaluation.Reason,
	}}
}

type healthResponseOutput struct {
	Body struct {
		Status string `json:"status" doc:"Service health state." example:"ok"`
	}
}

// liteLLMRequestBody isolates the evolving upstream envelope from strict scan requests.
// Only texts and input_type participate in evaluation.
type liteLLMRequestBody struct {
	_                                struct{}       `additionalProperties:"true"`
	Texts                            []string       `json:"texts" doc:"Extracted text items to scan."`
	InputType                        domain.Scope   `json:"input_type,omitempty" doc:"Guardrail execution scope: request or response." enum:"request,response"`
	RequestData                      map[string]any `json:"request_data,omitempty" doc:"Opaque caller metadata; not evaluated."`
	LiteLLMCallID                    string         `json:"litellm_call_id,omitempty"`
	LiteLLMTraceID                   string         `json:"litellm_trace_id,omitempty"`
	LiteLLMVersion                   string         `json:"litellm_version,omitempty"`
	RequestHeaders                   map[string]any `json:"request_headers,omitempty" doc:"Opaque forwarded headers; not used for authentication."`
	AdditionalProviderSpecificParams map[string]any `json:"additional_provider_specific_params,omitempty" doc:"Only the policy key is read: a configured policy name selecting the evaluated policy. Other keys are accepted and ignored."`
	Images                           []any          `json:"images,omitempty" doc:"Accepted but not evaluated or rewritten."`
	Tools                            []any          `json:"tools,omitempty" doc:"Accepted but not evaluated or rewritten."`
	ToolCalls                        []any          `json:"tool_calls,omitempty" doc:"Accepted but not evaluated or rewritten."`
	StructuredMessages               []any          `json:"structured_messages,omitempty" doc:"Accepted but not evaluated or rewritten."`
}

func (b liteLLMRequestBody) toDomain() domain.Request {
	scope := b.InputType
	if scope == "" {
		scope = domain.ScopeRequest
	}
	return domain.Request{Texts: b.Texts, InputType: scope, RequestData: b.RequestData}
}

type liteLLMRequestInput struct{ Body liteLLMRequestBody }

type liteLLMResponseBody struct {
	Action        domain.Decision `json:"action" enum:"NONE,BLOCKED,GUARDRAIL_INTERVENED"`
	BlockedReason *string         `json:"blocked_reason,omitempty" doc:"Reason supplied when the action is BLOCKED."`
	Texts         []string        `json:"texts" doc:"Text items aligned one to one with the request, in the same order."`
}

type liteLLMResponseOutput struct{ Body liteLLMResponseBody }
