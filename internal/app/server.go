package app

import (
	"fmt"
	"net/http"

	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/internal/domain"
	"github.com/g1lom/guardrail-serve/internal/guardrails"
	"github.com/g1lom/guardrail-serve/internal/httpapi"
	"github.com/g1lom/guardrail-serve/internal/resources"
)

func NewServer(cfg config.Config) (*http.Server, error) {
	handler, err := NewHandler(cfg)
	if err != nil {
		return nil, err
	}

	return &http.Server{
		Addr:    cfg.ListenAddr(),
		Handler: handler,
	}, nil
}

func NewHandler(cfg config.Config) (http.Handler, error) {
	secretPatterns, err := resources.LoadPatterns(cfg.GuardrailsConfigDir, "detect_secret_contextual_patterns.yaml")
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

	secretGuardrail, err := guardrails.NewDetectSecretGuardrail(cfg.SecretMask, secretPatterns)
	if err != nil {
		return nil, fmt.Errorf("build detect_secret guardrail: %w", err)
	}
	piiGuardrail, err := guardrails.NewDetectPIIGuardrail(cfg.SecretMask, piiPatterns)
	if err != nil {
		return nil, fmt.Errorf("build detect_pii guardrail: %w", err)
	}
	promptGuardrail, err := guardrails.NewPromptInjectionGuardrail(promptPatterns)
	if err != nil {
		return nil, fmt.Errorf("build prompt_injection guardrail: %w", err)
	}

	maxLengthGuardrail := guardrails.NewMaxLengthGuardrail(cfg.MaxTextItems, cfg.MaxTextChars)
	registry := domain.NewRegistry(maxLengthGuardrail, secretGuardrail, piiGuardrail, promptGuardrail)
	apiHandler := httpapi.NewHandler(cfg, registry, maxLengthGuardrail, secretGuardrail, piiGuardrail, promptGuardrail)

	mux := http.NewServeMux()
	apiHandler.Register(mux)
	return mux, nil
}
