package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/httpapi"
	"github.com/g1lom/guardrail-serve/internal/observability"
	"github.com/g1lom/guardrail-serve/internal/policy"
)

func TestLiteLLMHandlerUsesConfiguredGuardrail(t *testing.T) {
	t.Parallel()

	handler, err := app.NewHandler(config.Config{
		SecretMask:           "[REDACTED]",
		LiteLLMDefaultPolicy: "detect_secret",
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

	if got, want := response["action"], "GUARDRAIL_INTERVENED"; got != want {
		t.Fatalf("decision = %v, want %v", got, want)
	}
}

func TestLiteLLMHandlerRejectsUnknownScope(t *testing.T) {
	t.Parallel()

	handler, err := app.NewHandler(config.Config{
		SecretMask:           "[REDACTED]",
		LiteLLMDefaultPolicy: "prompt_injection",
		MaxTextItems:         20,
		MaxTextChars:         20000,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	requestBody := map[string]any{
		"texts":      []string{"hello"},
		"input_type": "unknown",
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/beta/litellm_basic_guardrail_api", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnprocessableEntity)
	}
}

func TestHandlerRejectsTrailingJSONPayload(t *testing.T) {
	t.Parallel()

	handler, err := app.NewHandler(config.Config{
		SecretMask:           "[REDACTED]",
		LiteLLMDefaultPolicy: "detect_secret",
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
		LiteLLMDefaultPolicy: "detect_secret",
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
		LiteLLMDefaultPolicy: "detect_secret",
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
		LiteLLMDefaultPolicy: "detect_secret",
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
		LiteLLMDefaultPolicy: "detect_secret",
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

func TestHandlerReturnsBadGatewayWhenGuardrailExecutionFails(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	logger := observability.NewLogger(&logs, "json", "guardrail-serve")
	failing := failingDetector{name: "detect_secret", err: errors.New("provider unavailable")}
	steps := []policy.Step{{Detector: failing, Action: domain.ActionMask, Mask: policy.LiteralMask("[REDACTED]")}}
	scanPolicy, err := policy.NewPolicy("scan-detect-secret", domain.ModeEnforce, steps, steps)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := policy.NewCatalog(scanPolicy)
	if err != nil {
		t.Fatal(err)
	}

	apiHandler := httpapi.NewHandler(
		config.Config{SecretMask: "[REDACTED]", LiteLLMDefaultPolicy: scanPolicy.Name},
		logger,
		policy.NewEngine(nil),
		catalog,
		httpapi.ScanPolicies{Secrets: scanPolicy, PII: scanPolicy, PromptInjection: scanPolicy},
	)
	mux := http.NewServeMux()
	apiHandler.Register(mux)
	handler := apiHandler.WithObservability(mux)

	for _, route := range []string{"/scan/secrets", "/v1/guardrails/scan-detect-secret", "/beta/litellm_basic_guardrail_api"} {
		request := httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{"texts":["token=tok_456"],"input_type":"request"}`))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusBadGateway {
			t.Fatalf("%s: status = %d, want %d body=%s", route, recorder.Code, http.StatusBadGateway, recorder.Body.String())
		}
		var response map[string]string
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if got, want := response["detail"], "Guardrail execution failed."; got != want {
			t.Fatalf("detail = %q, want %q", got, want)
		}
	}
	if !strings.Contains(logs.String(), `"detector":"detect_secret"`) || strings.Contains(logs.String(), "tok_456") {
		t.Fatalf("logs must name the detector without text values: %s", logs.String())
	}
}

func TestHandlerServesDocsAndOpenAPIWithPrefix(t *testing.T) {
	t.Parallel()

	handler, err := app.NewHandler(config.Config{
		APIPrefix:            "/v1",
		ProjectName:          "guardrail-serve",
		APIVersion:           "0.1.0",
		SecretMask:           "[REDACTED]",
		LiteLLMDefaultPolicy: "detect_secret",
		MaxTextItems:         20,
		MaxTextChars:         20000,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	docsRequest := httptest.NewRequest(http.MethodGet, "/v1/docs", nil)
	docsRecorder := httptest.NewRecorder()
	handler.ServeHTTP(docsRecorder, docsRequest)

	if docsRecorder.Code != http.StatusOK {
		t.Fatalf("docs status = %d, want %d", docsRecorder.Code, http.StatusOK)
	}
	if body := docsRecorder.Body.String(); !strings.Contains(body, "/v1/openapi.json") {
		t.Fatalf("docs body does not reference prefixed openapi path: %q", body)
	}

	specRequest := httptest.NewRequest(http.MethodGet, "/v1/openapi.json", nil)
	specRecorder := httptest.NewRecorder()
	handler.ServeHTTP(specRecorder, specRequest)

	if specRecorder.Code != http.StatusOK {
		t.Fatalf("openapi status = %d, want %d", specRecorder.Code, http.StatusOK)
	}

	var spec struct {
		OpenAPI string                    `json:"openapi"`
		Info    map[string]any            `json:"info"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(specRecorder.Body.Bytes(), &spec); err != nil {
		t.Fatalf("decode openapi: %v", err)
	}
	if spec.OpenAPI == "" {
		t.Fatal("openapi version is empty")
	}
	if _, ok := spec.Paths["/scan/secrets"]; !ok {
		t.Fatalf("paths missing /scan/secrets: %#v", spec.Paths)
	}
	if _, ok := spec.Paths["/beta/litellm_basic_guardrail_api"]; !ok {
		t.Fatalf("paths missing /beta/litellm_basic_guardrail_api: %#v", spec.Paths)
	}
}

type failingDetector struct {
	name string
	err  error
}

func (f failingDetector) Name() string { return f.name }

func (f failingDetector) Supports(domain.Stage) bool { return true }

func (f failingDetector) BlockReason() string { return "failing" }

func (f failingDetector) Detect(context.Context, string) ([]domain.Detection, error) {
	return nil, f.err
}
