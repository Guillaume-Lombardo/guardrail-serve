package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The client speaks only the documented public HTTP API (README, ADR 0007).
// The wire types below are deliberately local: the evaluation command does not
// import any service package, so it can evaluate any deployment, including a
// different version of the service.

const (
	userAgent = "guardrail-eval/1"

	// DefaultTimeout bounds each request.
	DefaultTimeout = 10 * time.Second
	// DefaultMaxResponseBytes bounds each response body.
	DefaultMaxResponseBytes int64 = 4 << 20
)

// Decision is the documented guardrail decision enumeration.
type Decision string

const (
	DecisionNone       Decision = "NONE"
	DecisionBlocked    Decision = "BLOCKED"
	DecisionIntervened Decision = "GUARDRAIL_INTERVENED"
)

func (d Decision) valid() bool {
	return d == DecisionNone || d == DecisionBlocked || d == DecisionIntervened
}

// AuthScheme selects the header that carries the optional API key.
type AuthScheme string

const (
	AuthBearer AuthScheme = "bearer"
	AuthAPIKey AuthScheme = "x-api-key"
)

// ParseAuthScheme validates an auth scheme; empty means bearer.
func ParseAuthScheme(value string) (AuthScheme, error) {
	switch AuthScheme(value) {
	case "", AuthBearer:
		return AuthBearer, nil
	case AuthAPIKey:
		return AuthAPIKey, nil
	}
	return "", fmt.Errorf("auth scheme must be %q or %q, got %q", AuthBearer, AuthAPIKey, value)
}

// ErrorKind classifies a failed request. None of these kinds is a detection
// outcome: a failed request never counts as "not detected".
type ErrorKind string

const (
	// KindTransport covers connection, TLS, timeout and cancellation errors.
	KindTransport ErrorKind = "transport"
	// KindHTTPStatus is a non-2xx response.
	KindHTTPStatus ErrorKind = "http_status"
	// KindInvalidResponse is a 2xx response that does not match the contract.
	KindInvalidResponse ErrorKind = "invalid_response"
	// KindResponseTooLarge is a body above the configured bound.
	KindResponseTooLarge ErrorKind = "response_too_large"
	// KindLimitExceeded means the service payload limits blocked the case
	// before any detector ran.
	KindLimitExceeded ErrorKind = "limit_exceeded"
)

// RequestError describes a failed request without echoing request or
// response bodies, credentials or evaluated texts.
type RequestError struct {
	Kind    ErrorKind
	Status  int
	Message string
}

func (e *RequestError) Error() string { return string(e.Kind) + ": " + e.Message }

// PolicyResult is a decoded POST /v1/guardrails/{policy} response.
type PolicyResult struct {
	Decision Decision
	// Detectors lists the detector of each finding, in response order.
	Detectors []string
}

// ScanResult is a decoded POST /scan/* response.
type ScanResult struct {
	Decision Decision
}

// scanRoutes maps a detector name to its fixed single-detector route.
var scanRoutes = map[string]string{
	"detect_secret":    "/scan/secrets",
	"detect_pii":       "/scan/pii",
	"prompt_injection": "/scan/prompt-injection",
}

// ScanRouteFor returns the /scan route that runs exactly one detector.
func ScanRouteFor(detector string) (string, bool) {
	route, ok := scanRoutes[detector]
	return route, ok
}

// limitsGuardrail is the metadata.guardrail value of payload-limit blocks.
const limitsGuardrail = "max_length"

var policyNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ClientConfig configures a Client.
type ClientConfig struct {
	// BaseURL is the service root, optionally with the API_PREFIX path.
	BaseURL string
	// APIKey is optional. It is sent in the header chosen by AuthScheme.
	APIKey     string
	AuthScheme AuthScheme
	// AllowInsecureAuth permits sending APIKey over plain HTTP to a
	// non-loopback host.
	AllowInsecureAuth bool
	Timeout           time.Duration
	MaxResponseBytes  int64
}

// Client calls the guardrail HTTP API.
type Client struct {
	base       *url.URL
	apiKey     string
	scheme     AuthScheme
	maxBytes   int64
	timeout    time.Duration
	httpClient *http.Client
}

// NewClient validates the configuration. It performs no network access.
func NewClient(cfg ClientConfig) (*Client, error) {
	base, err := parseBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	scheme, err := ParseAuthScheme(string(cfg.AuthScheme))
	if err != nil {
		return nil, err
	}
	if cfg.APIKey != "" {
		if strings.ContainsAny(cfg.APIKey, " \t\r\n") {
			return nil, errors.New("API key must not contain whitespace")
		}
		if base.Scheme == "http" && !isLoopback(base.Hostname()) && !cfg.AllowInsecureAuth {
			return nil, errors.New("refusing to send an API key over plain http to a non-loopback host; use https or --allow-insecure-auth")
		}
	}
	timeout, maxBytes := cfg.Timeout, cfg.MaxResponseBytes
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if maxBytes == 0 {
		maxBytes = DefaultMaxResponseBytes
	}
	if timeout < 0 || maxBytes < 0 {
		return nil, errors.New("timeout and max response bytes must be positive")
	}
	return &Client{
		base: base, apiKey: cfg.APIKey, scheme: scheme, maxBytes: maxBytes, timeout: timeout,
		httpClient: &http.Client{
			// A redirect would resend credentials to another location.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, errors.New("base URL must be an absolute http or https URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("base URL must not contain credentials, a query or a fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = ""
	return parsed, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// BaseURL returns the normalized service root without credentials.
func (c *Client) BaseURL() string { return c.base.String() }

// Policy calls POST /v1/guardrails/{policy} with a single text.
func (c *Client) Policy(ctx context.Context, policyName string, input InputType, text string) (PolicyResult, error) {
	if !policyNamePattern.MatchString(policyName) {
		return PolicyResult{}, fmt.Errorf("policy name %q must match %s", policyName, policyNamePattern)
	}
	var wire struct {
		Decision Decision `json:"decision"`
		Findings *[]struct {
			TextIndex *int   `json:"text_index"`
			Detector  string `json:"detector"`
		} `json:"findings"`
	}
	if err := c.post(ctx, "/v1/guardrails/"+policyName, input, text, &wire); err != nil {
		return PolicyResult{}, err
	}
	if !wire.Decision.valid() || wire.Findings == nil {
		return PolicyResult{}, invalid("response lacks a valid decision or findings array")
	}
	result := PolicyResult{Decision: wire.Decision, Detectors: make([]string, 0, len(*wire.Findings))}
	for _, finding := range *wire.Findings {
		if finding.TextIndex == nil || *finding.TextIndex != 0 || finding.Detector == "" {
			return PolicyResult{}, invalid("finding lacks text_index 0 or detector")
		}
		result.Detectors = append(result.Detectors, finding.Detector)
	}
	// Findings-less BLOCKED can only come from payload limits (ADR 0007):
	// a blocking policy step always reports the finding that blocked.
	if result.Decision == DecisionBlocked && len(result.Detectors) == 0 {
		return PolicyResult{}, &RequestError{Kind: KindLimitExceeded, Message: "payload limits blocked the case before detection"}
	}
	return result, nil
}

// Scan calls a /scan route (see ScanRouteFor) with a single text.
func (c *Client) Scan(ctx context.Context, route string, input InputType, text string) (ScanResult, error) {
	var wire struct {
		Decision Decision `json:"decision"`
		Metadata struct {
			Guardrail string `json:"guardrail"`
		} `json:"metadata"`
	}
	if err := c.post(ctx, route, input, text, &wire); err != nil {
		return ScanResult{}, err
	}
	if !wire.Decision.valid() || wire.Metadata.Guardrail == "" {
		return ScanResult{}, invalid("response lacks a valid decision or metadata.guardrail")
	}
	if wire.Metadata.Guardrail == limitsGuardrail {
		return ScanResult{}, &RequestError{Kind: KindLimitExceeded, Message: "payload limits blocked the case before detection"}
	}
	return ScanResult{Decision: wire.Decision}, nil
}

func invalid(message string) *RequestError {
	return &RequestError{Kind: KindInvalidResponse, Message: message}
}

func (c *Client) post(ctx context.Context, path string, input InputType, text string, out any) error {
	body, err := json.Marshal(struct {
		Texts     []string  `json:"texts"`
		InputType InputType `json:"input_type"`
	}{Texts: []string{text}, InputType: input})
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	target := *c.base
	target.Path += path

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)
	switch {
	case c.apiKey == "":
	case c.scheme == AuthAPIKey:
		request.Header.Set("X-API-Key", c.apiKey)
	default:
		request.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		return c.transportError(ctx, err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return &RequestError{Kind: KindHTTPStatus, Status: response.StatusCode, Message: fmt.Sprintf("HTTP %d %s", response.StatusCode, http.StatusText(response.StatusCode))}
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, c.maxBytes+1))
	if err != nil {
		return c.transportError(ctx, err)
	}
	if int64(len(data)) > c.maxBytes {
		return &RequestError{Kind: KindResponseTooLarge, Status: response.StatusCode, Message: fmt.Sprintf("response body exceeds %d bytes", c.maxBytes)}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return invalid("response is not the documented JSON object")
	}
	return nil
}

// transportError reports connection-level failures. It never includes the
// request URL beyond what the network error itself names (host and port).
func (c *Client) transportError(ctx context.Context, err error) *RequestError {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = urlErr.Err
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return &RequestError{Kind: KindTransport, Message: fmt.Sprintf("request exceeded the %s timeout", c.timeout)}
	case errors.Is(err, context.Canceled) || ctx.Err() != nil:
		return &RequestError{Kind: KindTransport, Message: "request canceled"}
	}
	// Only network-level errors are quoted: other errors (for example a
	// malformed HTTP response) can embed bytes sent by the remote server.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return &RequestError{Kind: KindTransport, Message: opErr.Error()}
	}
	return &RequestError{Kind: KindTransport, Message: "the server did not return a valid HTTP response"}
}
