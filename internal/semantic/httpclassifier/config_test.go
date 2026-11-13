package httpclassifier

import (
	"strings"
	"testing"
	"time"
)

func validConfig() Config {
	return Config{
		URL:         "http://127.0.0.1:8080/classify",
		Format:      FormatScores,
		Threshold:   0.5,
		Timeout:     time.Second,
		FailureMode: FailClosed,
	}
}

func TestParseFormat(t *testing.T) {
	for input, want := range map[string]Format{
		"scores":        FormatScores,
		" tei_predict ": FormatTEIPredict,
	} {
		got, err := ParseFormat(input)
		if err != nil || got != want {
			t.Fatalf("ParseFormat(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "SCORES", "tei", "openai"} {
		if _, err := ParseFormat(input); err == nil {
			t.Fatalf("ParseFormat(%q) succeeded", input)
		}
	}
}

func TestParseFailureMode(t *testing.T) {
	for input, want := range map[string]FailureMode{"open": FailOpen, "closed": FailClosed} {
		got, err := ParseFailureMode(input)
		if err != nil || got != want {
			t.Fatalf("ParseFailureMode(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "fail-open", "OPEN"} {
		if _, err := ParseFailureMode(input); err == nil {
			t.Fatalf("ParseFailureMode(%q) succeeded", input)
		}
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	tests := map[string]func(*Config){
		"empty url":          func(c *Config) { c.URL = "" },
		"relative url":       func(c *Config) { c.URL = "/classify" },
		"ftp url":            func(c *Config) { c.URL = "ftp://127.0.0.1/classify" },
		"no host":            func(c *Config) { c.URL = "http:///classify" },
		"embedded user":      func(c *Config) { c.URL = "http://user:pass@127.0.0.1/classify" },
		"fragment":           func(c *Config) { c.URL = "http://127.0.0.1/classify#x" },
		"missing format":     func(c *Config) { c.Format = "" },
		"unknown format":     func(c *Config) { c.Format = "tei" },
		"missing failure":    func(c *Config) { c.FailureMode = "" },
		"unknown failure":    func(c *Config) { c.FailureMode = "maybe" },
		"zero threshold":     func(c *Config) { c.Threshold = 0 },
		"negative threshold": func(c *Config) { c.Threshold = -0.1 },
		"threshold above 1":  func(c *Config) { c.Threshold = 1.0001 },
		"zero timeout":       func(c *Config) { c.Timeout = 0 },
		"negative timeout":   func(c *Config) { c.Timeout = -time.Second },
		"negative response":  func(c *Config) { c.MaxResponseBytes = -1 },
		"tiny chunk":         func(c *Config) { c.ChunkRunes = 8 },
		"overlap too large":  func(c *Config) { c.ChunkRunes = 100; c.ChunkOverlapRunes = 26 },
		"negative overlap":   func(c *Config) { c.ChunkOverlapRunes = -1 },
		"negative batch":     func(c *Config) { c.BatchSize = -1 },
		"negative chunks":    func(c *Config) { c.MaxChunks = -1 },
		"blank label":        func(c *Config) { c.MaliciousLabels = []string{"MALICIOUS", " "} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("New succeeded with invalid config")
			}
		})
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	classifier, err := New(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	cfg := classifier.cfg
	if cfg.modelName != DefaultModelName || cfg.maxResponse != DefaultMaxResponseBytes ||
		cfg.chunkRunes != DefaultChunkRunes || cfg.overlapRunes != DefaultChunkOverlapRunes ||
		cfg.batchSize != DefaultBatchSize || cfg.maxChunks != DefaultMaxChunks ||
		len(cfg.labels) != 1 || cfg.labels[0] != DefaultMaliciousLabel {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestNewConfigErrorsDoNotLeakCredentials(t *testing.T) {
	cfg := validConfig()
	cfg.URL = "http://user:hunter2@127.0.0.1/classify"
	_, err := New(cfg)
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("expected an error without credentials, got %v", err)
	}
}

func TestDefaultOverlapShrinksWithSmallChunks(t *testing.T) {
	cfg := validConfig()
	cfg.ChunkRunes = 40
	classifier, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if classifier.cfg.overlapRunes != 10 {
		t.Fatalf("overlap = %d, want 10", classifier.cfg.overlapRunes)
	}
}

func TestNewUsesNormalizedEnumValues(t *testing.T) {
	cfg := validConfig()
	cfg.FailureMode, cfg.Format = " open ", " tei_predict "
	classifier, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if classifier.cfg.failureMode != FailOpen || classifier.cfg.format != FormatTEIPredict {
		t.Fatalf("enum values were not normalized: %+v", classifier.cfg)
	}
}
