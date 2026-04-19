package domain

import "context"

type Decision string

const (
	DecisionNone                Decision = "NONE"
	DecisionBlocked             Decision = "BLOCKED"
	DecisionGuardrailIntervened Decision = "GUARDRAIL_INTERVENED"
)

type Scope string

const (
	ScopeRequest  Scope = "request"
	ScopeResponse Scope = "response"
)

func (s Scope) IsValid() bool {
	return s == ScopeRequest || s == ScopeResponse
}

type Request struct {
	Texts              []string         `json:"texts"`
	Images             []string         `json:"images"`
	Tools              []map[string]any `json:"tools"`
	ToolCalls          []map[string]any `json:"tool_calls"`
	StructuredMessages []map[string]any `json:"structured_messages"`
	RequestData        map[string]any   `json:"request_data"`
	InputType          Scope            `json:"input_type"`
}

func (r *Request) Normalize() {
	if r.Texts == nil {
		r.Texts = []string{}
	}
	if r.Images == nil {
		r.Images = []string{}
	}
	if r.Tools == nil {
		r.Tools = []map[string]any{}
	}
	if r.ToolCalls == nil {
		r.ToolCalls = []map[string]any{}
	}
	if r.StructuredMessages == nil {
		r.StructuredMessages = []map[string]any{}
	}
	if r.RequestData == nil {
		r.RequestData = map[string]any{}
	}
	if r.InputType == "" {
		r.InputType = ScopeRequest
	}
}

type Response struct {
	Decision Decision       `json:"decision"`
	Texts    []string       `json:"texts"`
	Metadata map[string]any `json:"metadata"`
	Reason   *string        `json:"reason"`
}

type Payload struct {
	Texts []string
	Scope Scope
}

type Result struct {
	Texts    []string
	Modified bool
	Decision Decision
	Reason   *string
	Metadata map[string]any
}

type Guardrail interface {
	Name() string
	Supports(Scope) bool
	Apply(context.Context, Payload) Result
}
