package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/g1lom/guardrail-serve/internal/domain"
)

type scanRequestBody struct {
	Texts              []string         `json:"texts,omitempty" doc:"Text items to scan."`
	Images             []string         `json:"images,omitempty" doc:"Currently unsupported placeholder for future multimodal support."`
	Tools              []map[string]any `json:"tools,omitempty" doc:"Currently unsupported placeholder for future tool-aware evaluation."`
	ToolCalls          []map[string]any `json:"tool_calls,omitempty" doc:"Currently unsupported placeholder for future tool-call evaluation."`
	StructuredMessages []map[string]any `json:"structured_messages,omitempty" doc:"Currently unsupported placeholder for future structured chat payloads."`
	RequestData        map[string]any   `json:"request_data,omitempty" doc:"Currently unsupported placeholder for future request metadata."`
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
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
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
