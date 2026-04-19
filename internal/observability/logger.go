package observability

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

const (
	LogFormatHuman = "human"
	LogFormatJSON  = "json"
)

func NormalizeLogFormat(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case LogFormatJSON:
		return LogFormatJSON
	case "text", LogFormatHuman:
		return LogFormatHuman
	default:
		return LogFormatHuman
	}
}

func NewDefaultLogger(format, service string) *slog.Logger {
	return NewLogger(os.Stdout, format, service)
}

func NewLogger(writer io.Writer, format, service string) *slog.Logger {
	options := &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				if timestamp, ok := attr.Value.Any().(time.Time); ok {
					attr.Value = slog.StringValue(timestamp.UTC().Format(time.RFC3339Nano))
				}
			}
			return attr
		},
	}

	var handler slog.Handler
	switch NormalizeLogFormat(format) {
	case LogFormatJSON:
		handler = slog.NewJSONHandler(writer, options)
	default:
		handler = slog.NewTextHandler(writer, options)
	}

	return slog.New(handler).With("service", service)
}
