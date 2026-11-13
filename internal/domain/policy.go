package domain

import (
	"context"
	"fmt"
)

// Stage is the policy evaluation point. Transport scopes map onto stages:
// request texts are evaluated by the input stage, response texts by the output stage.
type Stage string

const (
	StageInput  Stage = "input"
	StageOutput Stage = "output"
)

// Stages lists the valid stages in their canonical order.
func Stages() []Stage { return []Stage{StageInput, StageOutput} }

func ParseStage(value string) (Stage, error) {
	switch Stage(value) {
	case StageInput, StageOutput:
		return Stage(value), nil
	}
	return "", fmt.Errorf("unknown stage %q (expected input or output)", value)
}

// StageForScope maps the transport input_type onto a policy stage.
func StageForScope(scope Scope) (Stage, bool) {
	switch scope {
	case ScopeRequest:
		return StageInput, true
	case ScopeResponse:
		return StageOutput, true
	}
	return "", false
}

// Action is applied to every finding produced by one policy step.
type Action string

const (
	ActionBlock    Action = "block"
	ActionMask     Action = "mask"
	ActionAnnotate Action = "annotate"
)

func ParseAction(value string) (Action, error) {
	switch Action(value) {
	case ActionBlock, ActionMask, ActionAnnotate:
		return Action(value), nil
	}
	return "", fmt.Errorf("unknown action %q (expected block, mask or annotate)", value)
}

// Mode controls whether a policy applies its actions or only reports them.
type Mode string

const (
	ModeEnforce Mode = "enforce"
	ModeDetect  Mode = "detect"
)

func ParseMode(value string) (Mode, error) {
	switch Mode(value) {
	case ModeEnforce, ModeDetect:
		return Mode(value), nil
	}
	return "", fmt.Errorf("unknown mode %q (expected enforce or detect)", value)
}

// Detection is a raw detector match. Start and End are byte offsets into the
// scanned text, start inclusive and end exclusive, on UTF-8 rune boundaries.
type Detection struct {
	Rule  string
	Type  string
	Start int
	End   int
	Score *float64
}

// Detector finds spans in a single text item. Implementations must respect
// cancellation and must not expose transport or provider types in this contract.
// Deterministic detectors remain deterministic; optional classifiers may use I/O.
type Detector interface {
	Name() string
	Supports(Stage) bool
	Detect(context.Context, string) ([]Detection, error)
	// BlockReason is a fixed, value-free explanation used when a finding blocks.
	BlockReason() string
}

// Finding is one detection attributed to one original text item.
// Start and End are Unicode code point (rune) offsets into the original text,
// start inclusive and end exclusive. Findings never carry matched values.
type Finding struct {
	TextIndex int
	Detector  string
	Type      string
	Rule      string
	Start     int
	End       int
	Score     *float64
	Action    Action
}
