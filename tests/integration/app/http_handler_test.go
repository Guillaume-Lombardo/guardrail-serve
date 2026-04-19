package app_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/internal/observability"
)

func TestLiteLLMHandlerUsesConfiguredGuardrail(t *testing.T) {
	t.Parallel()

	handler, err := app.NewHandler(config.Config{
		SecretMask:           "[REDACTED]",
		LiteLLMGuardrailName: "detect_secret",
		MaxTextItems:         20,
		MaxTextChars:         20000,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	requestBody := map[string]any{
		"texts":      []string{"token=tok_456"},
		"input_type": "request",
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/beta/litellm_basic_guardrail_api", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if got, want := response["decision"], "GUARDRAIL_INTERVENED"; got != want {
		t.Fatalf("decision = %v, want %v", got, want)
	}
}

func TestLiteLLMHandlerRejectsUnsupportedScope(t *testing.T) {
	t.Parallel()

	handler, err := app.NewHandler(config.Config{
		SecretMask:           "[REDACTED]",
		LiteLLMGuardrailName: "prompt_injection",
		MaxTextItems:         20,
		MaxTextChars:         20000,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	requestBody := map[string]any{
		"texts":      []string{"hello"},
		"input_type": "response",
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/beta/litellm_basic_guardrail_api", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestHandlerRejectsTrailingJSONPayload(t *testing.T) {
	t.Parallel()

	handler, err := app.NewHandler(config.Config{
		SecretMask:           "[REDACTED]",
		LiteLLMGuardrailName: "detect_secret",
		MaxTextItems:         20,
		MaxTextChars:         20000,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/scan/secrets",
		bytes.NewBufferString(`{"texts":["token=tok_456"],"input_type":"request"}{"extra":true}`),
	)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}

	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, want := response["detail"], "Invalid JSON request body."; got != want {
		t.Fatalf("detail = %q, want %q", got, want)
	}
}

func TestHandlerReturnsJSONForMethodNotAllowed(t *testing.T) {
	t.Parallel()

	handler, err := app.NewHandler(config.Config{
		SecretMask:           "[REDACTED]",
		LiteLLMGuardrailName: "detect_secret",
		MaxTextItems:         20,
		MaxTextChars:         20000,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/scan/secrets", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
	if got, want := recorder.Header().Get("Content-Type"), "application/json"; got != want {
		t.Fatalf("content-type = %q, want %q", got, want)
	}

	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, want := response["detail"], "Method not allowed."; got != want {
		t.Fatalf("detail = %q, want %q", got, want)
	}
}

func TestHandlerPropagatesRequestIDAndLogsRequestContext(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := observability.NewLogger(&logs, "json", "guardrail-serve")
	handler, err := app.NewHandlerWithLogger(config.Config{
		ProjectName:          "guardrail-serve",
		LogFormat:            "json",
		SecretMask:           "[REDACTED]",
		LiteLLMGuardrailName: "detect_secret",
		MaxTextItems:         20,
		MaxTextChars:         20000,
	}, logger)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	requestBody := map[string]any{
		"texts":      []string{"token=tok_456"},
		"input_type": "request",
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/scan/secrets", bytes.NewReader(body))
	request.Header.Set("X-Request-ID", "req-123")
	request.Header.Set("User-Agent", "integration-test")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got, want := recorder.Header().Get("X-Request-ID"), "req-123"; got != want {
		t.Fatalf("X-Request-ID = %q, want %q", got, want)
	}

	lines := bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n"))
	if len(lines) == 0 {
		t.Fatal("log output is empty")
	}

	var payload map[string]any
	if err := json.Unmarshal(lines[len(lines)-1], &payload); err != nil {
		t.Fatalf("unmarshal log payload: %v", err)
	}

	if got, want := payload["request_id"], "req-123"; got != want {
		t.Fatalf("request_id = %v, want %v", got, want)
	}
	if got, want := payload["guardrail"], "detect_secret"; got != want {
		t.Fatalf("guardrail = %v, want %v", got, want)
	}
	if got, want := payload["input_type"], "request"; got != want {
		t.Fatalf("input_type = %v, want %v", got, want)
	}
	if got, want := payload["decision"], "GUARDRAIL_INTERVENED"; got != want {
		t.Fatalf("decision = %v, want %v", got, want)
	}
	if got, want := payload["status_code"], float64(http.StatusOK); got != want {
		t.Fatalf("status_code = %v, want %v", got, want)
	}
	if got, want := payload["path"], "/scan/secrets"; got != want {
		t.Fatalf("path = %v, want %v", got, want)
	}
	if payload["msg"] != "request completed" {
		t.Fatalf("msg = %v, want request completed", payload["msg"])
	}
}

func TestHandlerRejectsRequestWithoutTexts(t *testing.T) {
	t.Parallel()

	handler, err := app.NewHandler(config.Config{
		SecretMask:           "[REDACTED]",
		LiteLLMGuardrailName: "detect_secret",
		MaxTextItems:         20,
		MaxTextChars:         20000,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	requestBody := map[string]any{
		"input_type": "request",
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/scan/secrets", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}

	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, want := response["detail"], "At least one text item is required."; got != want {
		t.Fatalf("detail = %q, want %q", got, want)
	}
}

func TestHandlerRejectsUnsupportedNonTextFields(t *testing.T) {
	t.Parallel()

	handler, err := app.NewHandler(config.Config{
		SecretMask:           "[REDACTED]",
		LiteLLMGuardrailName: "detect_secret",
		MaxTextItems:         20,
		MaxTextChars:         20000,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	requestBody := map[string]any{
		"texts":      []string{"hello"},
		"images":     []string{"image-1"},
		"input_type": "request",
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/scan/secrets", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}

	var response map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, want := response["detail"], "Unsupported request fields: images."; got != want {
		t.Fatalf("detail = %q, want %q", got, want)
	}
}
