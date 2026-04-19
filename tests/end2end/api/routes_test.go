package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
)

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()

	handler, err := app.NewHandler(config.Config{
		SecretMask:           "[REDACTED]",
		LiteLLMGuardrailName: "detect_secret",
		MaxTextItems:         20,
		MaxTextChars:         20000,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	return handler
}

func TestEndToEndScanSecretsRedactsContextualPassword(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	requestBody := map[string]any{
		"texts":      []string{"login=foo password=abc123"},
		"input_type": "request",
	}
	body, _ := json.Marshal(requestBody)

	request := httptest.NewRequest(http.MethodPost, "/scan/secrets", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response struct {
		Decision string         `json:"decision"`
		Texts    []string       `json:"texts"`
		Metadata map[string]any `json:"metadata"`
		Reason   *string        `json:"reason"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response.Decision != "GUARDRAIL_INTERVENED" {
		t.Fatalf("decision = %s", response.Decision)
	}
	if got, want := response.Texts[0], "login=foo password=[REDACTED]"; got != want {
		t.Fatalf("texts[0] = %q, want %q", got, want)
	}
	if got, want := response.Metadata["guardrail"], "detect_secret"; got != want {
		t.Fatalf("metadata.guardrail = %v, want %v", got, want)
	}
	if response.Reason != nil {
		t.Fatalf("reason = %v, want nil", *response.Reason)
	}
}

func TestEndToEndLiteLLMBasicGuardrailReturnsNoneWhenNoSecret(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t)
	requestBody := map[string]any{
		"texts":      []string{"bonjour tout le monde"},
		"input_type": "request",
	}
	body, _ := json.Marshal(requestBody)

	request := httptest.NewRequest(http.MethodPost, "/beta/litellm_basic_guardrail_api", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response struct {
		Decision string         `json:"decision"`
		Texts    []string       `json:"texts"`
		Metadata map[string]any `json:"metadata"`
		Reason   *string        `json:"reason"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if response.Decision != "NONE" {
		t.Fatalf("decision = %s, want NONE", response.Decision)
	}
	if got, want := response.Texts[0], "bonjour tout le monde"; got != want {
		t.Fatalf("texts[0] = %q, want %q", got, want)
	}
	if got, want := response.Metadata["guardrail"], "detect_secret"; got != want {
		t.Fatalf("metadata.guardrail = %v, want %v", got, want)
	}
	if response.Reason != nil {
		t.Fatalf("reason = %v, want nil", *response.Reason)
	}
}
