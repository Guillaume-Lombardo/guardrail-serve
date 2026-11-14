// Package systemone implements semantic.PromptInjectionDetector with TypeSafe's
// System One API (model Jev): a Judge that asks one typed, fixed question per
// masked text, and a Cascade that asks it only inside a gray zone of a primary
// classifier's score. See README.md and ADR 0021.
package systemone

import (
	"bytes"
	"context"
	"io"
	"net/http"
)

// client posts one question per request to the configured endpoint only.
type client struct {
	endpoint    string
	model       string
	key         APIKey
	question    Question
	maxResponse int64
	http        *http.Client
}

// newHTTPClient never follows redirects and never uses proxies from the
// environment, so the key is sent only to the configured host.
func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ask sends the already masked text and returns the validated verdict.
func (c *client) ask(ctx context.Context, masked string) (verdict, error) {
	body, err := encodeRequest(c.model, c.question, masked)
	if err != nil {
		return verdict{}, newError(FailureTransport)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return verdict{}, newError(FailureTransport)
	}
	request.Header.Set("Authorization", "Bearer "+*c.key.value)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "guardrail-serve")

	response, err := c.http.Do(request)
	if err != nil {
		return verdict{}, err
	}
	defer func() {
		// Drain a bounded amount so the connection can be reused.
		_, _ = io.CopyN(io.Discard, response.Body, c.maxResponse)
		_ = response.Body.Close()
	}()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return verdict{}, statusError(response.StatusCode)
	}
	if response.ContentLength > c.maxResponse {
		return verdict{}, newError(FailureResponseTooLarge)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, c.maxResponse+1))
	if err != nil {
		return verdict{}, err
	}
	if int64(len(payload)) > c.maxResponse {
		return verdict{}, newError(FailureResponseTooLarge)
	}
	return decodeResponse(payload, c.question)
}
