package systemone

import (
	"context"
	"errors"
	"net/http"
	"strconv"
)

// Outcome classifies one judgment. Values are stable strings, safe for logs,
// metadata and metric labels.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"

	// FailureCanceled: the caller's context ended. Always returned as an error.
	FailureCanceled Outcome = "canceled"
	// FailureTimeout: the judge timeout elapsed.
	FailureTimeout Outcome = "timeout"
	// FailureTransport: the request could not be sent or the response read.
	FailureTransport Outcome = "transport"
	// FailureMasking: masking failed; no request was sent.
	FailureMasking Outcome = "masking_failed"
	// FailureTextTooLarge: the masked text exceeds the limit; no request was sent.
	FailureTextTooLarge Outcome = "text_too_large"
	// FailureUnauthorized: HTTP 401 or 403.
	FailureUnauthorized Outcome = "unauthorized"
	// FailurePaymentRequired: HTTP 402, the prepaid balance is exhausted.
	FailurePaymentRequired Outcome = "payment_required"
	// FailureRateLimited: HTTP 429.
	FailureRateLimited Outcome = "rate_limited"
	// FailureOverloaded: HTTP 529.
	FailureOverloaded Outcome = "overloaded"
	// FailureRejected: HTTP 400, 413 or 422, the provider rejected this input.
	// Always returned as an error, like the other input-provoked failures.
	FailureRejected Outcome = "rejected_input"
	// FailureStatus: any other non-2xx status.
	FailureStatus Outcome = "status"
	// FailureResponseTooLarge: the response body exceeds the limit.
	FailureResponseTooLarge Outcome = "response_too_large"
	// FailureInvalidResponse: the response does not match the contract.
	FailureInvalidResponse Outcome = "invalid_response"
	// FailureInvalidProbability: a probability, score or confidence is out of domain.
	FailureInvalidProbability Outcome = "invalid_probability"
)

// Outcomes lists every Outcome, for label allowlists.
func Outcomes() []Outcome {
	return []Outcome{
		OutcomeSuccess, FailureCanceled, FailureTimeout, FailureTransport, FailureMasking,
		FailureTextTooLarge, FailureUnauthorized, FailurePaymentRequired, FailureRateLimited,
		FailureOverloaded, FailureRejected, FailureStatus, FailureResponseTooLarge, FailureInvalidResponse,
		FailureInvalidProbability,
	}
}

// Error reports a judgment failure. Its message holds only the failure kind
// and, for HTTP status failures, the status code: never scanned text, never
// response content, never headers, the API key or the endpoint URL.
type Error struct {
	Kind   Outcome
	Status int
	cause  error
}

func (e *Error) Error() string {
	if e.Status != 0 {
		return "systemone judge: " + string(e.Kind) + " " + strconv.Itoa(e.Status)
	}
	return "systemone judge: " + string(e.Kind)
}

// Unwrap exposes only context errors, so errors.Is works for cancellation and
// deadlines without leaking transport error text (which embeds the URL).
func (e *Error) Unwrap() error { return e.cause }

func newError(kind Outcome) *Error { return &Error{Kind: kind} }

func statusError(status int) *Error {
	kind := FailureStatus
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		kind = FailureUnauthorized
	case http.StatusPaymentRequired:
		kind = FailurePaymentRequired
	case http.StatusTooManyRequests:
		kind = FailureRateLimited
	case 529:
		kind = FailureOverloaded
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		kind = FailureRejected
	}
	return &Error{Kind: kind, Status: status}
}

// toFailure maps an error raised while calling the API to an *Error. parent is
// the caller's context, call the context carrying the judge timeout.
func toFailure(parent, call context.Context, err error) *Error {
	if parentErr := parent.Err(); parentErr != nil {
		return &Error{Kind: FailureCanceled, cause: parentErr}
	}
	var known *Error
	if errors.As(err, &known) {
		return known
	}
	if call.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return &Error{Kind: FailureTimeout, cause: context.DeadlineExceeded}
	}
	return newError(FailureTransport)
}
