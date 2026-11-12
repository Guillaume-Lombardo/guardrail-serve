package httpapi

import (
	"bytes"
	"encoding/json"

	"github.com/g1lom/guardrail-serve/internal/domain"
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

func newScanResponseOutput(response domain.Response) *scanResponseOutput {
	return &scanResponseOutput{
		Body: scanResponseBody{
			Decision: response.Decision,
			Texts:    response.Texts,
			Metadata: response.Metadata,
			Reason:   response.Reason,
		},
	}
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
	AdditionalProviderSpecificParams map[string]any `json:"additional_provider_specific_params,omitempty" doc:"Accepted but not evaluated."`
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
