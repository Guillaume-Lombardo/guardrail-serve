package httpclassifier

import (
	"context"
	"errors"
	"strconv"
)

// FailureKind classifies why a detection did not produce a score. Kinds are
// stable strings, safe to log and to expose in metadata.
type FailureKind string

const (
	FailureCanceled         FailureKind = "canceled"
	FailureTimeout          FailureKind = "timeout"
	FailureTransport        FailureKind = "transport"
	FailureStatus           FailureKind = "status"
	FailureResponseTooLarge FailureKind = "response_too_large"
	FailureInvalidResponse  FailureKind = "invalid_response"
	FailureInvalidScore     FailureKind = "invalid_score"
	FailureTooManyChunks    FailureKind = "too_many_chunks"
)

// Error reports a detection failure. Its message holds only the failure kind
// and, for HTTP status failures, the status code: never scanned text, never
// response content and never the endpoint URL.
type Error struct {
	Kind   FailureKind
	Status int
	cause  error
}

func (e *Error) Error() string {
	if e.Kind == FailureStatus && e.Status != 0 {
		return "http classifier: " + string(e.Kind) + " " + strconv.Itoa(e.Status)
	}
	return "http classifier: " + string(e.Kind)
}

// Unwrap exposes only context errors so errors.Is(err, context.Canceled) and
// errors.Is(err, context.DeadlineExceeded) work without leaking transport
// error text (which embeds the endpoint URL).
func (e *Error) Unwrap() error { return e.cause }

func newError(kind FailureKind) *Error { return &Error{Kind: kind} }

// toFailure maps an error raised while calling the sidecar to an *Error.
// parent is the caller's context, call the context carrying the client timeout.
func toFailure(parent, call context.Context, err error) *Error {
	var known *Error
	if errors.As(err, &known) {
		return known
	}
	if parentErr := parent.Err(); parentErr != nil {
		return &Error{Kind: FailureCanceled, cause: parentErr}
	}
	if call.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return &Error{Kind: FailureTimeout, cause: context.DeadlineExceeded}
	}
	return newError(FailureTransport)
}
