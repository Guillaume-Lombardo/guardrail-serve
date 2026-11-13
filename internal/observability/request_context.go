package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type requestContextKey struct{}

type RequestContext struct {
	RequestID   string
	Method      string
	Path        string
	RemoteAddr  string
	UserAgent   string
	Guardrail   string
	Policy      string
	InputType   string
	Decision    string
	ErrorDetail string
	StatusCode  int
	TextCount   int
	// FindingCount is the only finding information logged; values never are.
	FindingCount int
	StartedAt    time.Time
}

func NewRequestContext(request *http.Request) *RequestContext {
	requestID := request.Header.Get("X-Request-ID")
	if !validRequestID(requestID) {
		requestID = generateRequestID()
	}

	return &RequestContext{
		RequestID:  requestID,
		Method:     request.Method,
		Path:       request.URL.Path,
		RemoteAddr: request.RemoteAddr,
		UserAgent:  boundedUserAgent(request.UserAgent()),
		StartedAt:  time.Now().UTC(),
	}
}

func WithRequestContext(ctx context.Context, metadata *RequestContext) context.Context {
	return context.WithValue(ctx, requestContextKey{}, metadata)
}

func GetRequestContext(ctx context.Context) (*RequestContext, bool) {
	metadata, ok := ctx.Value(requestContextKey{}).(*RequestContext)
	return metadata, ok
}

func (r *RequestContext) Attrs(duration time.Duration) []slog.Attr {
	attrs := []slog.Attr{
		slog.String("request_id", r.RequestID),
		slog.String("method", r.Method),
		slog.String("path", r.Path),
		slog.Int("status_code", r.StatusCode),
		slog.Int64("duration_ms", duration.Milliseconds()),
	}

	if r.RemoteAddr != "" {
		attrs = append(attrs, slog.String("remote_addr", r.RemoteAddr))
	}
	if r.UserAgent != "" {
		attrs = append(attrs, slog.String("user_agent", r.UserAgent))
	}
	if r.Guardrail != "" {
		attrs = append(attrs, slog.String("guardrail", r.Guardrail))
	}
	if r.Policy != "" {
		attrs = append(attrs, slog.String("policy", r.Policy))
	}
	if r.InputType != "" {
		attrs = append(attrs, slog.String("input_type", r.InputType))
	}
	if r.Decision != "" {
		attrs = append(attrs, slog.String("decision", r.Decision))
	}
	if r.TextCount > 0 {
		attrs = append(attrs, slog.Int("text_count", r.TextCount))
	}
	if r.Decision != "" {
		attrs = append(attrs, slog.Int("finding_count", r.FindingCount))
	}
	if r.ErrorDetail != "" {
		attrs = append(attrs, slog.String("error_detail", r.ErrorDetail))
	}

	return attrs
}

func generateRequestID() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(bytes)
}

// Request IDs accept only 1-128 ASCII letters, digits, dots, underscores and hyphens.
func validRequestID(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func boundedUserAgent(value string) string {
	// Bound work before sanitizing, then discard a partial final rune.
	if len(value) > 256 {
		value = value[:256]
	}
	value = strings.ToValidUTF8(value, "")
	return value
}
