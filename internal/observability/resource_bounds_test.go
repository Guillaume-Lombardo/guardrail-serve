package observability

import (
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRequestMetadataBounds(t *testing.T) {
	for _, id := range []string{"valid.ID_123-xyz", strings.Repeat("a", 128), strings.Repeat("x", 129), "bad id", "é", "bad:colon", " padded "} {
		r := httptest.NewRequest("GET", "/health/", nil)
		r.Header.Set("X-Request-ID", id)
		r.Header.Set("User-Agent", strings.Repeat("界", 100)+"\xff")
		m := NewRequestContext(r)
		valid := id == "valid.ID_123-xyz" || id == strings.Repeat("a", 128)
		if valid && m.RequestID != id {
			t.Error("valid id changed")
		}
		if !valid && m.RequestID == id {
			t.Error("invalid id accepted")
		}
		if len(m.RequestID) > 128 || len(m.UserAgent) > 256 || !utf8.ValidString(m.UserAgent) {
			t.Error("metadata unbounded or invalid UTF-8")
		}
	}
}
