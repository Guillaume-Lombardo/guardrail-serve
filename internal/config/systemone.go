package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/g1lom/guardrail-serve/internal/semantic/httpclassifier"
	"github.com/g1lom/guardrail-serve/internal/semantic/systemone"
)

// maxKeyFileBytes bounds SYSTEMONE_API_KEY_FILE; a key is far smaller.
const maxKeyFileBytes = 16 << 10

// SystemOne is static operator configuration for the optional System One
// judge. The zero value is disabled. Parse errors are reported by Resolve even
// when disabled, so a mistyped variable never passes silently.
type SystemOne struct {
	Enabled bool
	Mode    systemone.Mode
	Judge   systemone.Config
	Zone    systemone.Zone
	// KeyFile is read by Resolve, only when enabled; it takes the place of Judge.APIKey.
	KeyFile  string
	parseErr error
}

func loadSystemOne() SystemOne {
	s := SystemOne{
		Mode: systemone.Mode(getEnv("SYSTEMONE_MODE", string(systemone.ModeCascade))),
		Judge: systemone.Config{
			BaseURL:     getEnv("SYSTEMONE_BASE_URL", ""),
			Model:       getEnv("SYSTEMONE_MODEL", ""),
			Question:    systemone.Question(getEnv("SYSTEMONE_QUESTION", string(systemone.QuestionNoul))),
			Threshold:   systemone.DefaultThreshold,
			Timeout:     3 * time.Second,
			FailureMode: httpclassifier.FailureMode(getEnv("SYSTEMONE_FAILURE_MODE", string(httpclassifier.FailClosed))),
		},
		KeyFile: getEnv("SYSTEMONE_API_KEY_FILE", ""),
	}
	fail := func(err error) {
		if s.parseErr == nil {
			s.parseErr = err
		}
	}
	// Enumerations are checked here so that a typo fails startup even while disabled.
	if mode, err := systemone.ParseMode(string(s.Mode)); err != nil {
		fail(fmt.Errorf("SYSTEMONE_MODE: %w", err))
	} else {
		s.Mode = mode
	}
	if question, err := systemone.ParseQuestion(string(s.Judge.Question)); err != nil {
		fail(fmt.Errorf("SYSTEMONE_QUESTION: %w", err))
	} else {
		s.Judge.Question = question
	}
	if failureMode, err := httpclassifier.ParseFailureMode(string(s.Judge.FailureMode)); err != nil {
		fail(fmt.Errorf("SYSTEMONE_FAILURE_MODE: %w", err))
	} else {
		s.Judge.FailureMode = failureMode
	}
	if v := strings.TrimSpace(os.Getenv("SYSTEMONE_ENABLED")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			fail(errors.New("SYSTEMONE_ENABLED must be a boolean"))
		}
		s.Enabled = b
	}
	if v := strings.TrimSpace(os.Getenv("SYSTEMONE_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			fail(errors.New("SYSTEMONE_TIMEOUT must be a positive duration"))
		}
		s.Judge.Timeout = d
	}
	if v := strings.TrimSpace(os.Getenv("SYSTEMONE_THRESHOLD")); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			fail(errors.New("SYSTEMONE_THRESHOLD must be a number in (0, 1]"))
		}
		s.Judge.Threshold = f
	}
	if v := strings.TrimSpace(os.Getenv("SYSTEMONE_MAX_TEXT_RUNES")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			fail(errors.New("SYSTEMONE_MAX_TEXT_RUNES must be a positive integer"))
		}
		s.Judge.MaxTextRunes = n
	}
	// Never echo the value: it is a credential.
	if v := os.Getenv("SYSTEMONE_API_KEY"); v != "" {
		key, err := systemone.NewAPIKey(v)
		if err != nil {
			fail(fmt.Errorf("SYSTEMONE_API_KEY: %w", err))
		}
		s.Judge.APIKey = key
	}
	lower, lowerSet := os.LookupEnv("SYSTEMONE_ZONE_LOWER")
	upper, upperSet := os.LookupEnv("SYSTEMONE_ZONE_UPPER")
	lower, upper = strings.TrimSpace(lower), strings.TrimSpace(upper)
	lowerSet, upperSet = lowerSet && lower != "", upperSet && upper != ""
	if s.Mode == systemone.ModeCascade && s.Enabled && (!lowerSet || !upperSet) {
		fail(errors.New("SYSTEMONE_ZONE_LOWER and SYSTEMONE_ZONE_UPPER are required in cascade mode"))
	}
	if lowerSet {
		f, err := strconv.ParseFloat(lower, 64)
		if err != nil {
			fail(errors.New("SYSTEMONE_ZONE_LOWER must be a number in [0, 1]"))
		}
		s.Zone.Lower = f
	}
	if upperSet {
		f, err := strconv.ParseFloat(upper, 64)
		if err != nil {
			fail(errors.New("SYSTEMONE_ZONE_UPPER must be a number in [0, 1]"))
		}
		s.Zone.Upper = f
	}
	return s
}

// ResolvedSystemOne is a validated, enabled configuration.
type ResolvedSystemOne struct {
	Mode  systemone.Mode
	Judge systemone.Config
	Zone  systemone.Zone
}

// Resolve validates the configuration without network access and returns nil
// when disabled. When enabled it reads the key file and requires exactly one
// key source. semanticEnabled is the primary classifier's state: cascade
// requires it, judge_only forbids it so that nothing is silently ignored.
func (s SystemOne) Resolve(semanticEnabled bool) (*ResolvedSystemOne, error) {
	if s.parseErr != nil {
		return nil, s.parseErr
	}
	if !s.Enabled {
		return nil, nil
	}
	mode, err := systemone.ParseMode(string(s.Mode))
	if err != nil {
		return nil, fmt.Errorf("SYSTEMONE_MODE: %w", err)
	}
	switch {
	case mode == systemone.ModeCascade && !semanticEnabled:
		return nil, errors.New("SYSTEMONE_MODE=cascade requires SEMANTIC_ENABLED=true")
	case mode == systemone.ModeJudgeOnly && semanticEnabled:
		return nil, errors.New("SYSTEMONE_MODE=judge_only requires SEMANTIC_ENABLED=false")
	}
	if mode == systemone.ModeCascade {
		if err := s.Zone.Validate(); err != nil {
			return nil, fmt.Errorf("SYSTEMONE_ZONE_LOWER/SYSTEMONE_ZONE_UPPER: %w", err)
		}
	}
	judge := s.Judge
	switch {
	case s.KeyFile != "" && judge.APIKey.Set():
		return nil, errors.New("set only one of SYSTEMONE_API_KEY_FILE and SYSTEMONE_API_KEY")
	case s.KeyFile != "":
		key, err := readKeyFile(s.KeyFile)
		if err != nil {
			return nil, err
		}
		judge.APIKey = key
	case !judge.APIKey.Set():
		return nil, errors.New("SYSTEMONE_API_KEY_FILE or SYSTEMONE_API_KEY is required when SYSTEMONE_ENABLED=true")
	}
	return &ResolvedSystemOne{Mode: mode, Judge: judge, Zone: s.Zone}, nil
}

// readKeyFile reads a bounded key file. Errors never include its content or path.
func readKeyFile(path string) (systemone.APIKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return systemone.APIKey{}, errors.New("SYSTEMONE_API_KEY_FILE cannot be read")
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maxKeyFileBytes+1))
	if err != nil {
		return systemone.APIKey{}, errors.New("SYSTEMONE_API_KEY_FILE cannot be read")
	}
	if len(content) > maxKeyFileBytes {
		return systemone.APIKey{}, errors.New("SYSTEMONE_API_KEY_FILE is too large")
	}
	key, err := systemone.NewAPIKey(string(content))
	if err != nil {
		return systemone.APIKey{}, fmt.Errorf("SYSTEMONE_API_KEY_FILE: %w", err)
	}
	return key, nil
}
