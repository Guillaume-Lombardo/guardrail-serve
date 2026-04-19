package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

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
	mux.HandleFunc(h.path("/health/"), h.handleHealth)
	mux.HandleFunc(h.path("/scan/secrets"), h.wrapGuardrail(h.secret))
	mux.HandleFunc(h.path("/scan/pii"), h.wrapGuardrail(h.pii))
	mux.HandleFunc(h.path("/scan/prompt-injection"), h.wrapGuardrail(h.prompt))
	mux.HandleFunc(h.path("/beta/litellm_basic_guardrail_api"), h.handleLiteLLM)
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

func (h *Handler) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeMethodNotAllowed(writer, request)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) wrapGuardrail(guardrail domain.Guardrail) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeMethodNotAllowed(writer, request)
			return
		}
		setGuardrail(request.Context(), guardrail.Name())

		payload, ok := decodeRequest(writer, request)
		if !ok {
			return
		}
		if !validateScope(writer, request, payload.InputType, guardrail.Name(), guardrail.Supports(payload.InputType)) {
			return
		}

		response := h.applyChain(request.Context(), payload, guardrail)
		recordResponse(request.Context(), payload, response)
		writeJSON(writer, http.StatusOK, response)
	}
}

func (h *Handler) handleLiteLLM(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(writer, request)
		return
	}

	payload, ok := decodeRequest(writer, request)
	if !ok {
		return
	}

	guardrailName := h.config.LiteLLMGuardrailName
	setGuardrail(request.Context(), guardrailName)
	guardrail, exists := h.registry.Get(guardrailName)
	if !exists {
		writeError(writer, request, http.StatusInternalServerError, fmt.Sprintf("Unknown guardrail configured for LiteLLM: %s", guardrailName))
		return
	}

	if !validateScope(writer, request, payload.InputType, guardrailName, guardrail.Supports(payload.InputType)) {
		return
	}

	response := h.applyChain(request.Context(), payload, guardrail)
	recordResponse(request.Context(), payload, response)
	writeJSON(writer, http.StatusOK, response)
}

func (h *Handler) applyChain(ctx context.Context, request domain.Request, endpointGuardrail domain.Guardrail) domain.Response {
	payload := domain.Payload{
		Texts: request.Texts,
		Scope: request.InputType,
	}

	sizeResult := h.maxLength.Apply(ctx, payload)
	if sizeResult.Decision == domain.DecisionBlocked {
		return guardrails.ResponseFromResult(h.maxLength.Name(), request.Texts, sizeResult)
	}

	result := endpointGuardrail.Apply(ctx, payload)
	response := guardrails.ResponseFromResult(endpointGuardrail.Name(), request.Texts, result)
	if len(result.Metadata) > 0 {
		for key, value := range result.Metadata {
			response.Metadata[key] = value
		}
	}
	return response
}

func decodeRequest(writer http.ResponseWriter, request *http.Request) (domain.Request, bool) {
	var payload domain.Request
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		writeError(writer, request, http.StatusBadRequest, "Invalid JSON request body.")
		return domain.Request{}, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(writer, request, http.StatusBadRequest, "Invalid JSON request body.")
		return domain.Request{}, false
	}

	payload.Normalize()
	recordInputType(request.Context(), payload)
	if !payload.InputType.IsValid() {
		writeError(writer, request, http.StatusBadRequest, "Invalid input_type. Expected 'request' or 'response'.")
		return domain.Request{}, false
	}

	return payload, true
}

func validateScope(writer http.ResponseWriter, request *http.Request, scope domain.Scope, guardrailName string, valid bool) bool {
	if valid {
		return true
	}
	writeError(
		writer,
		request,
		http.StatusBadRequest,
		fmt.Sprintf("Guardrail '%s' does not support scope '%s'", guardrailName, scope),
	)
	return false
}

func writeMethodNotAllowed(writer http.ResponseWriter, request *http.Request) {
	writeError(writer, request, http.StatusMethodNotAllowed, "Method not allowed.")
}

func writeError(writer http.ResponseWriter, request *http.Request, status int, detail string) {
	if request != nil {
		recordError(request.Context(), detail)
	}
	writeJSON(writer, status, map[string]string{"detail": detail})
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(payload); err != nil {
		http.Error(writer, strings.TrimSpace(err.Error()), http.StatusInternalServerError)
	}
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

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}
