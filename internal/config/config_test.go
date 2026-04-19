package config

import "testing"

func TestLoadFallsBackForInvalidOrNonPositiveIntegers(t *testing.T) {
	t.Setenv("MAX_TEXT_ITEMS", "0")
	t.Setenv("MAX_TEXT_CHARS", "-42")

	cfg := Load()

	if got, want := cfg.MaxTextItems, 20; got != want {
		t.Fatalf("MaxTextItems = %d, want %d", got, want)
	}
	if got, want := cfg.MaxTextChars, 20000; got != want {
		t.Fatalf("MaxTextChars = %d, want %d", got, want)
	}
}

func TestLoadTrimsAndNormalizesPrefix(t *testing.T) {
	t.Setenv("API_PREFIX", " /v1/ ")

	cfg := Load()

	if got, want := cfg.APIPrefix, "/v1"; got != want {
		t.Fatalf("APIPrefix = %q, want %q", got, want)
	}
}

func TestLoadNormalizesLogFormat(t *testing.T) {
	t.Setenv("LOG_FORMAT", "TEXT")

	cfg := Load()

	if got, want := cfg.LogFormat, "human"; got != want {
		t.Fatalf("LogFormat = %q, want %q", got, want)
	}
}
