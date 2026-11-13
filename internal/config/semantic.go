package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/g1lom/guardrail-serve/internal/semantic/httpclassifier"
)

// Semantic is static operator configuration, never request metadata.
// The zero value disables the optional policy detector.
type Semantic struct {
	Enabled  bool
	HTTP     httpclassifier.Config
	parseErr error
}

func loadSemantic() Semantic {
	s := Semantic{HTTP: httpclassifier.Config{
		URL: getEnv("SEMANTIC_URL", ""), Format: httpclassifier.Format(getEnv("SEMANTIC_FORMAT", "scores")),
		Timeout: 2 * time.Second, Threshold: 0.9, FailureMode: httpclassifier.FailureMode(getEnv("SEMANTIC_FAILURE_MODE", "closed")),
	}}
	if v := strings.TrimSpace(os.Getenv("SEMANTIC_ENABLED")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			s.parseErr = fmt.Errorf("SEMANTIC_ENABLED must be a boolean")
		}
		s.Enabled = b
	}
	if v := strings.TrimSpace(os.Getenv("SEMANTIC_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			s.parseErr = fmt.Errorf("SEMANTIC_TIMEOUT must be a positive duration")
		}
		s.HTTP.Timeout = d
	}
	if v := strings.TrimSpace(os.Getenv("SEMANTIC_THRESHOLD")); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			s.parseErr = fmt.Errorf("SEMANTIC_THRESHOLD must be in (0, 1]")
		}
		s.HTTP.Threshold = f
	}
	if v := os.Getenv("SEMANTIC_MALICIOUS_LABELS"); v != "" {
		s.HTTP.MaliciousLabels = strings.Split(v, ",")
	}
	return s
}

// NewClassifier validates even disabled settings without making a network call.
// An unset URL is allowed only when disabled.
func (s Semantic) NewClassifier() (*httpclassifier.Classifier, error) {
	if s.parseErr != nil {
		return nil, s.parseErr
	}
	if !s.Enabled && s.HTTP.URL == "" && s.HTTP.Format == "" && s.HTTP.Timeout == 0 && s.HTTP.Threshold == 0 && s.HTTP.FailureMode == "" && len(s.HTTP.MaliciousLabels) == 0 {
		return nil, nil
	}
	c := s.HTTP
	if !s.Enabled && c.URL == "" {
		c.URL = "http://disabled.invalid"
	}
	classifier, err := httpclassifier.New(c)
	if err != nil {
		return nil, err
	}
	if !s.Enabled {
		return nil, nil
	}
	return classifier, nil
}
