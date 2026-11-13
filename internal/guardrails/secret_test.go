package guardrails

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/g1lom/guardrail-serve/internal/secrets"
	"github.com/g1lom/guardrail-serve/internal/textnorm"
)

func TestSecretNativeProjectsOriginalBytes(t *testing.T) {
	d, err := NewSecretDetector(nil)
	if err != nil {
		t.Fatal(err)
	}
	// NFKC expansion and stripped runes inside the value must map to original
	// byte spans, including complete graphemes, not scanner rune offsets.
	for _, text := range []string{"Été 🙂 password=Tr0u\u200bb4dor&3x", "🙂 password=ﬁve9Pass\u0301", "mot de pa\u200bsse：Tr0ub4dor9"} {
		norm := textnorm.Normalize(text)
		scanner, _ := secrets.New(secrets.DefaultConfig())
		fs, err := scanner.Scan(context.Background(), norm.Text())
		if err != nil {
			t.Fatal(err)
		}
		ds, err := d.Detect(context.Background(), text)
		if err != nil {
			t.Fatal(err)
		}
		if len(ds) == 0 || len(ds) != len(fs) {
			t.Fatal("missing findings")
		}
		for i, f := range fs {
			span, _ := norm.OriginalBytes(f.ByteStart, f.ByteEnd)
			got := ds[i]
			if got.Start != span.Start || got.End != span.End || got.Type != f.Type || got.Rule != f.Rule {
				t.Fatal("incorrect original projection")
			}
			if !utf8.ValidString(text[got.Start:got.End]) || got.Start == utf8.RuneCountInString(text[:got.Start]) {
				t.Fatal("fixture must distinguish byte and rune offsets")
			}
		}
	}
	for _, text := range []string{"password=bad\xffvalue", "password=bad�value"} {
		if ds, err := d.Detect(context.Background(), text); err == nil || len(ds) > 0 || strings.Contains(err.Error(), "bad") {
			t.Fatal("invalid text must fail safely")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Detect(ctx, "password=Tr0ub4dor9"); err != context.Canceled {
		t.Fatal(err)
	}
}
