package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/guardrails"
	"github.com/g1lom/guardrail-serve/internal/observability"
)

type Handler struct {
	config    config.Config
	logger    *slog.Logger
	registry  domain.Registry
	maxLength domain.Guardrail
	secret    domain.Guardrail
	pii       domain.Guardrail
	prompt    domain.Guardrail
}

func NewHandler(
	cfg config.Config,
	logger *slog.Logger,
	registry domain.Registry,
	maxLength domain.Guardrail,
	secret domain.Guardrail,
	pii domain.Guardrail,
	prompt domain.Guardrail,
) *Handler {
	return &Handler{
		config:    cfg,
		logger:    logger,
		registry:  registry,
		maxLength: maxLength,
		secret:    secret,
		pii:       pii,
		prompt:    prompt,
	}
}

func (h *Handler) Register(mux *http.ServeMux) {
	h.registerMethodFallbacks(mux)

	apiConfig := huma.DefaultConfig(h.config.ProjectName, h.config.APIVersion)
	apiConfig.DocsRenderer = huma.DocsRendererSwaggerUI
	apiConfig.Transformers = nil
	apiConfig.CreateHooks = nil

	api := humago.NewWithPrefix(mux, h.config.APIPrefix, apiConfig)

	huma.Register(api, huma.Operation{
		OperationID: "health",
		Method:      http.MethodGet,
		Path:        "/health/",
		Summary:     "Health check",
		Description: "Returns the service health state.",
		Tags:        []string{"system"},
	}, h.handleHealth)

	h.registerGuardrailOperation(api, "/scan/secrets", "scanSecrets", "Detect secrets in text payloads.", h.secret)
	h.registerGuardrailOperation(api, "/scan/pii", "scanPII", "Detect PII in text payloads.", h.pii)
	h.registerGuardrailOperation(api, "/scan/prompt-injection", "scanPromptInjection", "Detect prompt-injection patterns in text payloads.", h.prompt)

	huma.Register(api, huma.Operation{
		OperationID: "scanLiteLLMBasicGuardrail",
		Method:      http.MethodPost,
		Path:        "/beta/litellm_basic_guardrail_api",
		Summary:     "Run the configured LiteLLM guardrail",
		Description: "Executes the configured guardrail for the LiteLLM-compatible scan endpoint.",
		Tags:        []string{"scan", "beta"},
		Errors:      []int{http.StatusBadRequest, http.StatusBadGateway, http.StatusInternalServerError},
	}, h.handleLiteLLM)
}

func (h *Handler) registerMethodFallbacks(mux *http.ServeMux) {
	methodFallbacks := []string{
		h.path("/health/"),
		h.path("/scan/secrets"),
		h.path("/scan/pii"),
		h.path("/scan/prompt-injection"),
		h.path("/beta/litellm_basic_guardrail_api"),
	}

	for _, route := range methodFallbacks {
		mux.HandleFunc(route, func(writer http.ResponseWriter, request *http.Request) {
			writeMethodNotAllowed(writer, request)
		})
	}
}

func (h *Handler) registerGuardrailOperation(
	api huma.API,
	path string,
	operationID string,
	description string,
	guardrail domain.Guardrail,
) {
	huma.Register(api, huma.Operation{
		OperationID: operationID,
		Method:      http.MethodPost,
		Path:        path,
		Summary:     guardrail.Name(),
		Description: description,
		Tags:        []string{"scan"},
		Errors:      []int{http.StatusBadRequest, http.StatusBadGateway},
	}, func(ctx context.Context, input *scanRequestInput) (*scanResponseOutput, error) {
		return h.handleGuardrail(ctx, guardrail, input)
	})
}

func (h *Handler) WithObservability(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestMetadata := observability.NewRequestContext(request)
		ctx := observability.WithRequestContext(request.Context(), requestMetadata)
		request = request.WithContext(ctx)

		recorder := &statusRecorder{
			ResponseWriter: writer,
			statusCode:     http.StatusOK,
		}
		recorder.Header().Set("X-Request-ID", requestMetadata.RequestID)

		next.ServeHTTP(recorder, request)

		requestMetadata.StatusCode = recorder.statusCode
		h.logRequest(ctx, requestMetadata, time.Since(requestMetadata.StartedAt))
	})
}

func (h *Handler) path(route string) string {
	return h.config.APIPrefix + route
}

func (h *Handler) handleHealth(ctx context.Context, _ *struct{}) (*healthResponseOutput, error) {
	response := &healthResponseOutput{}
	response.Body.Status = "ok"
	return response, nil
}

func (h *Handler) handleGuardrail(
	ctx context.Context,
	guardrail domain.Guardrail,
	input *scanRequestInput,
) (*scanResponseOutput, error) {
	request := input.Body.toDomain()
	recordInputType(ctx, request)
	setGuardrail(ctx, guardrail.Name())

	if err := validateRequest(request); err != nil {
		return nil, err
	}
	if !guardrail.Supports(request.InputType) {
		return nil, newStatusDetailError(
			http.StatusBadRequest,
			fmt.Sprintf("Guardrail '%s' does not support scope '%s'", guardrail.Name(), request.InputType),
		)
	}

	response, err := h.applyChain(ctx, request, guardrail)
	if err != nil {
		return nil, h.handleGuardrailExecutionError(ctx, guardrail.Name(), err)
	}

	recordResponse(ctx, request, response)
	return newScanResponseOutput(response), nil
}

func (h *Handler) handleLiteLLM(ctx context.Context, input *scanRequestInput) (*scanResponseOutput, error) {
	request := input.Body.toDomain()
	recordInputType(ctx, request)

	guardrailName := h.config.LiteLLMGuardrailName
	setGuardrail(ctx, guardrailName)

	if err := validateRequest(request); err != nil {
		return nil, err
	}
	guardrail, exists := h.registry.Get(guardrailName)
	if !exists {
		return nil, newStatusDetailError(
			http.StatusInternalServerError,
			fmt.Sprintf("Unknown guardrail configured for LiteLLM: %s", guardrailName),
		)
	}

	if !guardrail.Supports(request.InputType) {
		return nil, newStatusDetailError(
			http.StatusBadRequest,
			fmt.Sprintf("Guardrail '%s' does not support scope '%s'", guardrailName, request.InputType),
		)
	}

	response, err := h.applyChain(ctx, request, guardrail)
	if err != nil {
		return nil, h.handleGuardrailExecutionError(ctx, guardrailName, err)
	}

	recordResponse(ctx, request, response)
	return newScanResponseOutput(response), nil
}

func (h *Handler) applyChain(ctx context.Context, request domain.Request, endpointGuardrail domain.Guardrail) (domain.Response, error) {
	payload := domain.Payload{
		Texts: request.Texts,
		Scope: request.InputType,
	}

	sizeResult, err := h.maxLength.Apply(ctx, payload)
	if err != nil {
		return domain.Response{}, err
	}
	if sizeResult.Decision == domain.DecisionBlocked {
		return guardrails.ResponseFromResult(h.maxLength.Name(), request.Texts, sizeResult), nil
	}

	result, err := endpointGuardrail.Apply(ctx, payload)
	if err != nil {
		return domain.Response{}, err
	}
	response := guardrails.ResponseFromResult(endpointGuardrail.Name(), request.Texts, result)
	if len(result.Metadata) > 0 {
		for key, value := range result.Metadata {
			response.Metadata[key] = value
		}
	}
	return response, nil
}

func (h *Handler) logRequest(ctx context.Context, requestMetadata *observability.RequestContext, duration time.Duration) {
	level := slog.LevelInfo
	message := "request completed"
	switch {
	case requestMetadata.StatusCode >= http.StatusInternalServerError:
		level = slog.LevelError
		message = "request failed"
	case requestMetadata.StatusCode >= http.StatusBadRequest:
		level = slog.LevelWarn
		message = "request rejected"
	}

	h.logger.LogAttrs(ctx, level, message, requestMetadata.Attrs(duration)...)
}

func (h *Handler) handleGuardrailExecutionError(ctx context.Context, guardrailName string, err error) error {
	h.logger.ErrorContext(
		ctx,
		"guardrail execution failed",
		"guardrail", guardrailName,
		"error", err,
	)

	return newStatusDetailError(http.StatusBadGateway, "Guardrail execution failed.")
}

func recordInputType(ctx context.Context, payload domain.Request) {
	requestMetadata, ok := observability.GetRequestContext(ctx)
	if !ok {
		return
	}
	requestMetadata.InputType = string(payload.InputType)
	requestMetadata.TextCount = len(payload.Texts)
}

func setGuardrail(ctx context.Context, name string) {
	requestMetadata, ok := observability.GetRequestContext(ctx)
	if !ok {
		return
	}
	requestMetadata.Guardrail = name
}

func recordResponse(ctx context.Context, payload domain.Request, response domain.Response) {
	requestMetadata, ok := observability.GetRequestContext(ctx)
	if !ok {
		return
	}
	requestMetadata.InputType = string(payload.InputType)
	requestMetadata.Decision = string(response.Decision)
	requestMetadata.TextCount = len(payload.Texts)
	if guardrailName, ok := response.Metadata["guardrail"].(string); ok {
		requestMetadata.Guardrail = guardrailName
	}
}

func recordError(ctx context.Context, detail string) {
	requestMetadata, ok := observability.GetRequestContext(ctx)
	if !ok {
		return
	}
	requestMetadata.ErrorDetail = detail
}

func validateRequestPayload(payload domain.Request) (string, bool) {
	if len(payload.Texts) == 0 {
		return "At least one text item is required.", false
	}

	unsupportedFields := make([]string, 0, 5)
	if len(payload.Images) > 0 {
		unsupportedFields = append(unsupportedFields, "images")
	}
	if len(payload.Tools) > 0 {
		unsupportedFields = append(unsupportedFields, "tools")
	}
	if len(payload.ToolCalls) > 0 {
		unsupportedFields = append(unsupportedFields, "tool_calls")
	}
	if len(payload.StructuredMessages) > 0 {
		unsupportedFields = append(unsupportedFields, "structured_messages")
	}
	if len(payload.RequestData) > 0 {
		unsupportedFields = append(unsupportedFields, "request_data")
	}

	if len(unsupportedFields) > 0 {
		sort.Strings(unsupportedFields)
		return fmt.Sprintf("Unsupported request fields: %s.", strings.Join(unsupportedFields, ", ")), false
	}

	return "", true
}

func validateRequest(payload domain.Request) error {
	if !payload.InputType.IsValid() {
		return newStatusDetailError(http.StatusBadRequest, "Invalid input_type. Expected 'request' or 'response'.")
	}

	if detail, ok := validateRequestPayload(payload); !ok {
		return newStatusDetailError(http.StatusBadRequest, detail)
	}

	return nil
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}
