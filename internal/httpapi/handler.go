package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/guardrails"
)

type Handler struct {
	config    config.Config
	registry  domain.Registry
	maxLength domain.Guardrail
	secret    domain.Guardrail
	pii       domain.Guardrail
	prompt    domain.Guardrail
}

func NewHandler(
	cfg config.Config,
	registry domain.Registry,
	maxLength domain.Guardrail,
	secret domain.Guardrail,
	pii domain.Guardrail,
	prompt domain.Guardrail,
) *Handler {
	return &Handler{
		config:    cfg,
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

func (h *Handler) path(route string) string {
	return h.config.APIPrefix + route
}

func (h *Handler) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeMethodNotAllowed(writer)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *Handler) wrapGuardrail(guardrail domain.Guardrail) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writeMethodNotAllowed(writer)
			return
		}

		payload, ok := decodeRequest(writer, request)
		if !ok {
			return
		}
		if !validateScope(writer, payload.InputType, guardrail.Name(), guardrail.Supports(payload.InputType)) {
			return
		}

		response := h.applyChain(payload, guardrail)
		writeJSON(writer, http.StatusOK, response)
	}
}

func (h *Handler) handleLiteLLM(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeMethodNotAllowed(writer)
		return
	}

	payload, ok := decodeRequest(writer, request)
	if !ok {
		return
	}

	guardrailName := h.config.LiteLLMGuardrailName
	guardrail, exists := h.registry.Get(guardrailName)
	if !exists {
		writeError(writer, http.StatusInternalServerError, fmt.Sprintf("Unknown guardrail configured for LiteLLM: %s", guardrailName))
		return
	}

	if !validateScope(writer, payload.InputType, guardrailName, guardrail.Supports(payload.InputType)) {
		return
	}

	response := h.applyChain(payload, guardrail)
	writeJSON(writer, http.StatusOK, response)
}

func (h *Handler) applyChain(request domain.Request, endpointGuardrail domain.Guardrail) domain.Response {
	payload := domain.Payload{
		Texts: request.Texts,
		Scope: request.InputType,
	}

	sizeResult := h.maxLength.Apply(payload)
	if sizeResult.Decision == domain.DecisionBlocked {
		return guardrails.ResponseFromResult(h.maxLength.Name(), request.Texts, sizeResult)
	}

	result := endpointGuardrail.Apply(payload)
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
		writeError(writer, http.StatusBadRequest, "Invalid JSON request body.")
		return domain.Request{}, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(writer, http.StatusBadRequest, "Invalid JSON request body.")
		return domain.Request{}, false
	}

	payload.Normalize()
	if !payload.InputType.IsValid() {
		writeError(writer, http.StatusBadRequest, "Invalid input_type. Expected 'request' or 'response'.")
		return domain.Request{}, false
	}

	return payload, true
}

func validateScope(writer http.ResponseWriter, scope domain.Scope, guardrailName string, valid bool) bool {
	if valid {
		return true
	}
	writeError(
		writer,
		http.StatusBadRequest,
		fmt.Sprintf("Guardrail '%s' does not support scope '%s'", guardrailName, scope),
	)
	return false
}

func writeMethodNotAllowed(writer http.ResponseWriter) {
	writeError(writer, http.StatusMethodNotAllowed, "Method not allowed.")
}

func writeError(writer http.ResponseWriter, status int, detail string) {
	writeJSON(writer, status, map[string]string{"detail": detail})
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(payload); err != nil {
		http.Error(writer, strings.TrimSpace(err.Error()), http.StatusInternalServerError)
	}
}
