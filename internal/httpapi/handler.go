package httpapi

import (
	"context"
	"errors"
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
	"github.com/g1lom/guardrail-serve/internal/observability"
	"github.com/g1lom/guardrail-serve/internal/policy"
)

// limitsGuardrail names the payload limit check in /scan metadata and logs.
const limitsGuardrail = "max_length"

// ScanPolicies holds the fixed single-detector policies behind /scan/*.
// They are built in code so policy file overrides never change these routes.
type ScanPolicies struct {
	Secrets              *policy.Policy
	PII                  *policy.Policy
	PromptInjection      *policy.Policy
	PromptInjectionRules []string
}

type scanRoute struct {
	path, operationID, description string
	guardrail                      string
	policy                         *policy.Policy
	reportRules                    []string
}

type Handler struct {
	config  config.Config
	logger  *slog.Logger
	engine  *policy.Engine
	catalog *policy.Catalog
	scan    []scanRoute
}

// NewHandler wires transports to the policy engine. The caller validates that
// cfg.LiteLLMDefaultPolicy exists in catalog.
func NewHandler(cfg config.Config, logger *slog.Logger, engine *policy.Engine, catalog *policy.Catalog, scan ScanPolicies) *Handler {
	return &Handler{
		config:  cfg,
		logger:  logger,
		engine:  engine,
		catalog: catalog,
		scan: []scanRoute{
			{path: "/scan/secrets", operationID: "scanSecrets", description: "Detect secrets in text payloads.", guardrail: "detect_secret", policy: scan.Secrets},
			{path: "/scan/pii", operationID: "scanPII", description: "Detect PII in text payloads.", guardrail: "detect_pii", policy: scan.PII},
			{
				path: "/scan/prompt-injection", operationID: "scanPromptInjection", description: "Detect prompt-injection patterns in text payloads.",
				guardrail: "prompt_injection", policy: scan.PromptInjection, reportRules: append([]string{}, scan.PromptInjectionRules...),
			},
		},
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
		MaxBodyBytes: (1 << 20) + 1,
		OperationID:  "health",
		Method:       http.MethodGet,
		Path:         "/health/",
		Summary:      "Health check",
		Description:  "Returns the service health state.",
		Tags:         []string{"system"},
	}, h.handleHealth)

	for _, route := range h.scan {
		h.registerScanOperation(api, route)
	}

	huma.Register(api, huma.Operation{
		MaxBodyBytes: (1 << 20) + 1,
		OperationID:  "evaluatePolicy",
		Method:       http.MethodPost,
		Path:         policyRoute,
		Summary:      "Evaluate a named policy",
		Description: "Runs the ordered detector chain of the named policy for the stage selected by input_type " +
			"and returns findings with rune offsets into the original texts. Unknown policies return 404.",
		Tags:   []string{"policy", "v1"},
		Errors: []int{http.StatusNotFound, http.StatusBadGateway},
	}, h.handlePolicy)

	huma.Register(api, huma.Operation{
		MaxBodyBytes: (1 << 20) + 1,
		OperationID:  "scanLiteLLMBasicGuardrail",
		Method:       http.MethodPost,
		Path:         "/beta/litellm_basic_guardrail_api",
		Summary:      "Run a policy for LiteLLM",
		Description: "Evaluates additional_provider_specific_params.policy, or the configured default policy when that key is absent. " +
			"Unknown or invalid policy selections return 400.",
		Tags:   []string{"scan", "beta"},
		Errors: []int{http.StatusBadRequest, http.StatusBadGateway},
	}, h.handleLiteLLM)
}

const policyRoute = "/v1/guardrails/{policy}"

func (h *Handler) registerMethodFallbacks(mux *http.ServeMux) {
	methodFallbacks := []string{
		h.path("/health/"),
		h.path(policyRoute),
		h.path("/beta/litellm_basic_guardrail_api"),
	}
	for _, route := range h.scan {
		methodFallbacks = append(methodFallbacks, h.path(route.path))
	}

	for _, route := range methodFallbacks {
		mux.HandleFunc(route, func(writer http.ResponseWriter, request *http.Request) {
			writeMethodNotAllowed(writer, request)
		})
	}
}

func (h *Handler) registerScanOperation(api huma.API, route scanRoute) {
	huma.Register(api, huma.Operation{
		MaxBodyBytes: (1 << 20) + 1,
		OperationID:  route.operationID,
		Method:       http.MethodPost,
		Path:         route.path,
		Summary:      route.guardrail,
		Description:  route.description,
		Tags:         []string{"scan"},
		Errors:       []int{http.StatusBadRequest, http.StatusBadGateway},
	}, func(ctx context.Context, input *scanRequestInput) (*scanResponseOutput, error) {
		return h.handleScan(ctx, route, input)
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

func (h *Handler) handleScan(ctx context.Context, route scanRoute, input *scanRequestInput) (*scanResponseOutput, error) {
	request := input.Body.toDomain()
	recordInputType(ctx, request)
	setGuardrail(ctx, route.guardrail)

	if err := validateRequest(request); err != nil {
		return nil, err
	}
	evaluation, err := h.evaluate(ctx, route.policy, request)
	if err != nil {
		return nil, err
	}
	if evaluation.LimitExceeded {
		setGuardrail(ctx, limitsGuardrail)
	}
	return newScanResponseOutput(route, evaluation), nil
}

func (h *Handler) handlePolicy(ctx context.Context, input *policyRequestInput) (*policyResponseOutput, error) {
	request := domain.Request{Texts: input.Body.Texts, InputType: input.Body.InputType, RequestData: input.Body.RequestData}
	if request.InputType == "" {
		request.InputType = domain.ScopeRequest
	}
	recordInputType(ctx, request)

	selected, err := h.lookupPolicy(ctx, input.Policy, http.StatusNotFound)
	if err != nil {
		return nil, err
	}
	evaluation, err := h.evaluate(ctx, selected, request)
	if err != nil {
		return nil, err
	}
	return newPolicyResponseOutput(evaluation), nil
}

func (h *Handler) handleLiteLLM(ctx context.Context, input *liteLLMRequestInput) (*liteLLMResponseOutput, error) {
	request := input.Body.toDomain()
	recordInputType(ctx, request)

	if err := validateRequest(request); err != nil {
		return nil, err
	}
	name := h.config.LiteLLMDefaultPolicy
	if raw, present := input.Body.AdditionalProviderSpecificParams["policy"]; present {
		selected, ok := raw.(string)
		if !ok || selected == "" {
			return nil, newStatusDetailError(http.StatusBadRequest, "additional_provider_specific_params.policy must be a non-empty policy name.")
		}
		name = selected
	}
	selected, err := h.lookupPolicy(ctx, name, http.StatusBadRequest)
	if err != nil {
		return nil, err
	}
	evaluation, err := h.evaluate(ctx, selected, request)
	if err != nil {
		return nil, err
	}

	response := liteLLMResponseBody{Action: evaluation.Decision, Texts: evaluation.Texts}
	if evaluation.Decision == domain.DecisionBlocked {
		response.BlockedReason = evaluation.Reason
	}
	return &liteLLMResponseOutput{Body: response}, nil
}

// lookupPolicy never falls back to another policy. Only syntactically valid
// names are echoed, so error details and logs cannot carry arbitrary input.
func (h *Handler) lookupPolicy(ctx context.Context, name string, status int) (*policy.Policy, error) {
	if selected, ok := h.catalog.Get(name); ok {
		setPolicy(ctx, selected.Name)
		return selected, nil
	}
	if !policy.ValidName(name) {
		return nil, newStatusDetailError(status, "Unknown policy.")
	}
	return nil, newStatusDetailError(status, fmt.Sprintf("Unknown policy '%s'.", name))
}

func (h *Handler) evaluate(ctx context.Context, selected *policy.Policy, request domain.Request) (policy.Evaluation, error) {
	stage, ok := domain.StageForScope(request.InputType)
	if !ok {
		return policy.Evaluation{}, newStatusDetailError(http.StatusBadRequest, "Invalid input_type. Expected 'request' or 'response'.")
	}
	evaluation, err := h.engine.Evaluate(ctx, selected, stage, request.Texts)
	if err != nil {
		return policy.Evaluation{}, h.handleGuardrailExecutionError(ctx, err)
	}
	recordEvaluation(ctx, evaluation)
	return evaluation, nil
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

func (h *Handler) handleGuardrailExecutionError(ctx context.Context, err error) error {
	detector := "unknown"
	var detectorErr *policy.DetectorError
	if errors.As(err, &detectorErr) {
		detector = detectorErr.Detector
	}
	h.logger.ErrorContext(
		ctx,
		"guardrail execution failed",
		"detector", detector,
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

func setPolicy(ctx context.Context, name string) {
	requestMetadata, ok := observability.GetRequestContext(ctx)
	if !ok {
		return
	}
	requestMetadata.Policy = name
}

// recordEvaluation logs counts only: findings, texts and matched values never reach logs.
func recordEvaluation(ctx context.Context, evaluation policy.Evaluation) {
	requestMetadata, ok := observability.GetRequestContext(ctx)
	if !ok {
		return
	}
	requestMetadata.Decision = string(evaluation.Decision)
	requestMetadata.FindingCount = len(evaluation.Findings)
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

	unsupportedFields := make([]string, 0, 4)
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
