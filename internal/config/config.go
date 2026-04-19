package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/g1lom/guardrail-serve/internal/observability"
)

type Config struct {
	APIPrefix            string
	APIPort              string
	APIVersion           string
	ProjectName          string
	SecretMask           string
	LiteLLMGuardrailName string
	GuardrailsConfigDir  string
	MaxTextItems         int
	MaxTextChars         int
	LogFormat            string
}

func Load() Config {
	return Config{
		APIPrefix:            normalizePrefix(getEnv("API_PREFIX", "")),
		APIPort:              getEnv("API_PORT", "8000"),
		APIVersion:           getEnv("API_VERSION", "0.1.0"),
		ProjectName:          getEnv("PROJECT_NAME", "guardrail-serve"),
		SecretMask:           getEnv("SECRET_MASK", "[REDACTED]"),
		LiteLLMGuardrailName: getEnv("LITELLM_GUARDRAIL_NAME", "detect_secret"),
		GuardrailsConfigDir:  strings.TrimSpace(os.Getenv("GUARDRAILS_CONFIG_DIR")),
		MaxTextItems:         getEnvInt("MAX_TEXT_ITEMS", 20),
		MaxTextChars:         getEnvInt("MAX_TEXT_CHARS", 20000),
		LogFormat:            observability.NormalizeLogFormat(os.Getenv("LOG_FORMAT")),
	}
}

func (c Config) ListenAddr() string {
	return ":" + c.APIPort
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getEnvInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}

	if parsed <= 0 {
		return fallback
	}

	return parsed
}

func normalizePrefix(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "/" {
		return ""
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return strings.TrimRight(value, "/")
}
