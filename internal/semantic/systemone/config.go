package systemone

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/g1lom/guardrail-serve/internal/semantic/httpclassifier"
)

// Question selects the typed System One question asked about each text.
// The wording of every question is fixed in code.
type Question string

const (
	QuestionNoul   Question = "noul"
	QuestionChoice Question = "choice"
	QuestionScore  Question = "score"
)

// ParseQuestion converts a user-facing value into a Question.
func ParseQuestion(value string) (Question, error) {
	switch question := Question(strings.TrimSpace(value)); question {
	case QuestionNoul, QuestionChoice, QuestionScore:
		return question, nil
	}
	return "", fmt.Errorf("unsupported question %q (expected noul, choice or score)", value)
}

func (q Question) String() string { return string(q) }

// Mode selects how the judge is combined with the primary classifier.
type Mode string

const (
	// ModeCascade asks the judge only when the primary score is in the zone.
	ModeCascade Mode = "cascade"
	// ModeJudgeOnly asks the judge for every non-blank text.
	ModeJudgeOnly Mode = "judge_only"
)

// ParseMode converts a user-facing value into a Mode.
func ParseMode(value string) (Mode, error) {
	switch mode := Mode(strings.TrimSpace(value)); mode {
	case ModeCascade, ModeJudgeOnly:
		return mode, nil
	}
	return "", fmt.Errorf("unsupported mode %q (expected cascade or judge_only)", value)
}

func (m Mode) String() string { return string(m) }

const redacted = "[REDACTED]"

const maxAPIKeyBytes = 4096

// APIKey holds the bearer key. Every formatting, encoding and logging path
// renders it redacted; only the client reads the value. The value sits behind a
// pointer so that even reflection-based printing of an enclosing unexported
// field shows an address, never the key.
type APIKey struct{ value *string }

// NewAPIKey trims surrounding whitespace (a trailing newline from a file) and
// rejects empty, oversized or header-unsafe keys. Errors never include the key.
func NewAPIKey(raw string) (APIKey, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return APIKey{}, errors.New("API key is empty")
	}
	if len(value) > maxAPIKeyBytes {
		return APIKey{}, fmt.Errorf("API key exceeds %d bytes", maxAPIKeyBytes)
	}
	for _, r := range value {
		if r <= ' ' || r >= 0x7f {
			return APIKey{}, errors.New("API key must be printable ASCII without spaces")
		}
	}
	return APIKey{value: &value}, nil
}

// Set reports whether a key is present.
func (k APIKey) Set() bool                     { return k.value != nil }
func (APIKey) String() string                  { return redacted }
func (APIKey) MarshalText() ([]byte, error)    { return []byte(redacted), nil }
func (APIKey) LogValue() slog.Value            { return slog.StringValue(redacted) }
func (k APIKey) Format(f fmt.State, verb rune) { _, _ = f.Write([]byte(redacted)) }

// Zone is the closed interval [Lower, Upper] of primary scores, both bounds
// inclusive, for which the cascade asks the judge.
type Zone struct {
	Lower float64
	Upper float64
}

// Validate requires finite bounds in [0, 1] with Lower <= Upper.
func (z Zone) Validate() error {
	for _, bound := range []float64{z.Lower, z.Upper} {
		if math.IsNaN(bound) || bound < 0 || bound > 1 {
			return errors.New("zone bounds must be in [0, 1]")
		}
	}
	if z.Lower > z.Upper {
		return errors.New("zone lower bound must not exceed the upper bound")
	}
	return nil
}

// Contains reports Lower <= score <= Upper.
func (z Zone) Contains(score float64) bool { return score >= z.Lower && score <= z.Upper }

const (
	// DefaultThreshold is the "yes" starting point suggested by the Noul
	// documentation; it is not calibrated on any corpus.
	DefaultThreshold = 0.7
	// DefaultMaxTextRunes bounds one masked text (the service default MAX_TEXT_CHARS).
	DefaultMaxTextRunes = 20000
	// DefaultMaxResponseBytes bounds a response body; answers are a few hundred bytes.
	DefaultMaxResponseBytes int64 = 64 << 10
	// EndpointPath is appended to the base URL.
	EndpointPath = "/v1/systemone"

	maxModelLength = 128
)

var modelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)

// Config is the complete judge constructor input. Nothing is read from the
// environment. Fields marked optional select documented defaults when zero.
type Config struct {
	// BaseURL (required): absolute https URL, or http for a loopback host; no
	// user info, query or fragment. A path prefix is kept (gateways).
	BaseURL string
	// Model (required): model ID or alias sent in the request, for example jev-1.14.0.
	Model string
	// APIKey (required): bearer key, sent only to BaseURL.
	APIKey APIKey
	// Question (required): noul, choice or score.
	Question Question
	// Threshold in (0, 1] (required): a probability >= Threshold triggers.
	Threshold float64
	// Timeout bounds one judgment, masking excluded (required, > 0).
	Timeout time.Duration
	// FailureMode (required): closed returns errors, open returns degraded.
	FailureMode httpclassifier.FailureMode
	// MaxTextRunes bounds one masked text (optional, default 20000).
	MaxTextRunes int
	// MaxResponseBytes bounds one response body (optional, default 64 KiB).
	MaxResponseBytes int64
}

type settings struct {
	endpoint    string
	model       string
	key         APIKey
	question    Question
	threshold   float64
	timeout     time.Duration
	failureMode httpclassifier.FailureMode
	maxRunes    int
	maxResponse int64
}

func (c Config) resolve() (settings, error) {
	endpoint, err := endpointURL(c.BaseURL)
	if err != nil {
		return settings{}, err
	}
	model := strings.TrimSpace(c.Model)
	if model == "" || len(model) > maxModelLength || !modelPattern.MatchString(model) {
		return settings{}, errors.New("model must be a non-empty model ID or alias")
	}
	if !c.APIKey.Set() {
		return settings{}, errors.New("API key is required")
	}
	question, err := ParseQuestion(string(c.Question))
	if err != nil {
		return settings{}, err
	}
	if math.IsNaN(c.Threshold) || c.Threshold <= 0 || c.Threshold > 1 {
		return settings{}, errors.New("threshold must be in (0, 1]")
	}
	if c.Timeout <= 0 {
		return settings{}, errors.New("timeout must be positive")
	}
	failureMode, err := httpclassifier.ParseFailureMode(string(c.FailureMode))
	if err != nil {
		return settings{}, err
	}
	resolved := settings{
		endpoint: endpoint, model: model, key: c.APIKey, question: question,
		threshold: c.Threshold, timeout: c.Timeout, failureMode: failureMode,
		maxRunes: c.MaxTextRunes, maxResponse: c.MaxResponseBytes,
	}
	if resolved.maxRunes == 0 {
		resolved.maxRunes = DefaultMaxTextRunes
	}
	if resolved.maxResponse == 0 {
		resolved.maxResponse = DefaultMaxResponseBytes
	}
	if resolved.maxRunes < 0 || resolved.maxResponse < 0 {
		return settings{}, errors.New("max text runes and max response bytes must be positive")
	}
	return resolved, nil
}

// endpointURL validates the base URL and appends EndpointPath. Error messages
// never echo the URL, which may carry a gateway account identifier.
func endpointURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("base URL is not a valid URL")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("base URL must be absolute and include a host")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !loopback(parsed.Hostname()) {
			return "", errors.New("base URL must use https (http is allowed only for loopback hosts)")
		}
	default:
		return "", errors.New("base URL must use https")
	}
	if parsed.User != nil {
		return "", errors.New("base URL must not embed credentials")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("base URL must not include a query or fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + EndpointPath
	parsed.RawPath = ""
	return parsed.String(), nil
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
