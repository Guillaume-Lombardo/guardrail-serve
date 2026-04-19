package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewLoggerJSONFormat(t *testing.T) {
	var buffer bytes.Buffer
	logger := NewLogger(&buffer, "json", "guardrail-serve")

	logger.InfoContext(context.Background(), "hello", "request_id", "req-123")

	var payload map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buffer.Bytes()), &payload); err != nil {
		t.Fatalf("unmarshal log payload: %v", err)
	}

	if got, want := payload["msg"], "hello"; got != want {
		t.Fatalf("msg = %v, want %v", got, want)
	}
	if got, want := payload["service"], "guardrail-serve"; got != want {
		t.Fatalf("service = %v, want %v", got, want)
	}
	if got, want := payload["request_id"], "req-123"; got != want {
		t.Fatalf("request_id = %v, want %v", got, want)
	}
}

func TestNewLoggerHumanFormat(t *testing.T) {
	var buffer bytes.Buffer
	logger := NewLogger(&buffer, "human", "guardrail-serve")

	logger.InfoContext(context.Background(), "hello", "request_id", "req-123")
	output := buffer.String()

	if !strings.Contains(output, "msg=hello") {
		t.Fatalf("output = %q, want msg=hello", output)
	}
	if !strings.Contains(output, "service=guardrail-serve") {
		t.Fatalf("output = %q, want service=guardrail-serve", output)
	}
	if !strings.Contains(output, "request_id=req-123") {
		t.Fatalf("output = %q, want request_id=req-123", output)
	}
}
