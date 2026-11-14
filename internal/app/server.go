package app

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/guardrails"
	"github.com/g1lom/guardrail-serve/internal/httpapi"
	"github.com/g1lom/guardrail-serve/internal/observability"
	"github.com/g1lom/guardrail-serve/internal/policy"
	"github.com/g1lom/guardrail-serve/internal/resources"
)

func NewServer(cfg config.Config) (*http.Server, error) {
	logger := observability.NewDefaultLogger(cfg.LogFormat, cfg.ProjectName)
	return NewServerWithLogger(cfg, logger)
}

func NewServerWithLogger(cfg config.Config, logger *slog.Logger) (*http.Server, error) {
	cfg.Runtime = cfg.Runtime.Defaults()
	handler, err := NewHandlerWithLogger(cfg, logger)
	if err != nil {
		return nil, err
	}

	return &http.Server{
		Addr:              cfg.ListenAddr(),
		MaxHeaderBytes:    32 << 10,
		ReadHeaderTimeout: cfg.Runtime.ReadHeaderTimeout,
		ReadTimeout:       cfg.Runtime.ReadTimeout,
		WriteTimeout:      cfg.Runtime.WriteTimeout,
		IdleTimeout:       cfg.Runtime.IdleTimeout,
		Handler:           handler,
	}, nil
}

func NewHandler(cfg config.Config) (http.Handler, error) {
	logger := observability.NewDefaultLogger(cfg.LogFormat, cfg.ProjectName)
	return NewHandlerWithLogger(cfg, logger)
}

func NewHandlerWithLogger(cfg config.Config, logger *slog.Logger) (http.Handler, error) {
	return NewHandlerWithRegistry(cfg, logger, nil)
}

// NewHandlerWithRegistry uses a caller-owned registry, or creates a fresh one.
func NewHandlerWithRegistry(cfg config.Config, logger *slog.Logger, registry *prometheus.Registry) (http.Handler, error) {
	cfg.Runtime = cfg.Runtime.Defaults()
	if err := cfg.Runtime.Validate(); err != nil {
		return nil, err
	}
	secretPatterns, err := resources.LoadSecretPatterns(cfg.GuardrailsConfigDir)
	if err != nil {
		return nil, fmt.Errorf("load secret patterns: %w", err)
	}
	piiPatterns, err := resources.LoadPatterns(cfg.GuardrailsConfigDir, "detect_pii_patterns.yaml")
	if err != nil {
		return nil, fmt.Errorf("load pii patterns: %w", err)
	}
	promptPatterns, err := resources.LoadPatterns(cfg.GuardrailsConfigDir, "detect_prompt_injection_patterns.yaml")
	if err != nil {
		return nil, fmt.Errorf("load prompt injection patterns: %w", err)
	}

	secret, err := guardrails.NewSecretDetector(secretPatterns)
	if err != nil {
		return nil, fmt.Errorf("build detect_secret detector: %w", err)
	}
	pii, err := guardrails.NewPIIDetector(piiPatterns)
	if err != nil {
		return nil, fmt.Errorf("build detect_pii detector: %w", err)
	}
	prompt, err := guardrails.NewPromptInjectionDetector(promptPatterns)
	if err != nil {
		return nil, fmt.Errorf("build prompt_injection detector: %w", err)
	}
	detectors := map[string]domain.Detector{secret.Name(): secret, pii.Name(): pii, prompt.Name(): prompt}

	judgeObserver := &observerSlot{}
	semanticPolicy, err := semanticDetector(cfg, logger, secret, pii, judgeObserver)
	if err != nil {
		return nil, err
	}
	if semanticPolicy != nil {
		detectors[semanticPolicy.Name()] = semanticPolicy
	}

	defaultMask := policy.LiteralMask(cfg.SecretMask)
	content, source, err := resources.LoadPolicies(cfg.GuardrailsConfigDir)
	if err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}
	catalog, err := policy.Parse(content, source, detectors, defaultMask)
	if err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}
	if cfg.LiteLLMDefaultPolicy == "" {
		cfg.LiteLLMDefaultPolicy = config.DefaultLiteLLMPolicy
	}
	if _, ok := catalog.Get(cfg.LiteLLMDefaultPolicy); !ok {
		return nil, fmt.Errorf("LITELLM_DEFAULT_POLICY %q is not defined in %s (defined: %s)",
			cfg.LiteLLMDefaultPolicy, source, strings.Join(catalog.Names(), ", "))
	}
	scan, err := scanPolicies(secret, pii, prompt, defaultMask)
	if err != nil {
		return nil, err
	}

	names := append(catalog.Names(), scan.Secrets.Name, scan.PII.Name, scan.PromptInjection.Name)
	detectorNames := []string{"max_length"}
	for name := range detectors {
		detectorNames = append(detectorNames, name)
	}
	metrics, err := observability.NewMetrics(registry, names, detectorNames)
	if err != nil {
		return nil, fmt.Errorf("register metrics: %w", err)
	}
	judgeObserver.target = metrics
	engine := policy.NewEngineWithObserver(guardrails.NewMaxLengthGuardrail(cfg.MaxTextItems, cfg.MaxTextChars), metrics)
	apiHandler := httpapi.NewHandler(cfg, logger, engine, catalog, scan)

	mux := http.NewServeMux()
	apiHandler.Register(mux)
	mux.Handle("GET "+cfg.APIPrefix+"/metrics", metrics)
	return runtimeHandler(cfg, apiHandler.WithObservability(mux)), nil
}

// scanPolicies reproduces the historical /scan contracts: one detector on both
// stages, enforced, masking with SECRET_MASK or blocking prompt injections.
func scanPolicies(secret, pii domain.Detector, prompt *guardrails.RegexDetector, mask policy.Mask) (httpapi.ScanPolicies, error) {
	single := func(detector domain.Detector, action domain.Action) (*policy.Policy, error) {
		steps := []policy.Step{{Detector: detector, Action: action, Mask: mask}}
		return policy.NewPolicy("scan-"+strings.ReplaceAll(detector.Name(), "_", "-"), domain.ModeEnforce, steps, steps)
	}
	var scan httpapi.ScanPolicies
	var err error
	if scan.Secrets, err = single(secret, domain.ActionMask); err != nil {
		return scan, err
	}
	if scan.PII, err = single(pii, domain.ActionMask); err != nil {
		return scan, err
	}
	if scan.PromptInjection, err = single(prompt, domain.ActionBlock); err != nil {
		return scan, err
	}
	scan.PromptInjectionRules = prompt.Rules()
	return scan, nil
}
