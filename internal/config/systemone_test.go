package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/g1lom/guardrail-serve/internal/semantic/systemone"
)

const envKey = "ts-config-test-key-42"

var systemOneVariables = []string{
	"SYSTEMONE_ENABLED", "SYSTEMONE_MODE", "SYSTEMONE_BASE_URL", "SYSTEMONE_MODEL", "SYSTEMONE_API_KEY",
	"SYSTEMONE_API_KEY_FILE", "SYSTEMONE_QUESTION", "SYSTEMONE_THRESHOLD", "SYSTEMONE_ZONE_LOWER",
	"SYSTEMONE_ZONE_UPPER", "SYSTEMONE_TIMEOUT", "SYSTEMONE_FAILURE_MODE", "SYSTEMONE_MAX_TEXT_RUNES",
}

func clearSystemOne(t *testing.T) {
	for _, key := range systemOneVariables {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
}

func enableSystemOne(t *testing.T) {
	t.Setenv("SYSTEMONE_ENABLED", "true")
	t.Setenv("SYSTEMONE_BASE_URL", "https://api.typesafe.ai")
	t.Setenv("SYSTEMONE_MODEL", "jev-1.14.0")
	t.Setenv("SYSTEMONE_API_KEY", envKey)
	t.Setenv("SYSTEMONE_ZONE_LOWER", "0.4")
	t.Setenv("SYSTEMONE_ZONE_UPPER", "0.9")
}

func TestSystemOneDefaultsDisabled(t *testing.T) {
	clearSystemOne(t)
	s := Load().SystemOne
	resolved, err := s.Resolve(false)
	if err != nil || resolved != nil || s.Enabled {
		t.Fatalf("default must be disabled: %+v %v", resolved, err)
	}
	if s.Mode != systemone.ModeCascade || s.Judge.Question != systemone.QuestionNoul || s.Judge.Threshold != 0.7 ||
		s.Judge.Timeout != 3*time.Second || s.Judge.FailureMode != "closed" || s.Judge.BaseURL != "" || s.Judge.Model != "" {
		t.Fatalf("documented defaults: %+v", s)
	}
}

func TestSystemOneEnvironment(t *testing.T) {
	clearSystemOne(t)
	enableSystemOne(t)
	resolved, err := Load().SystemOne.Resolve(true)
	if err != nil || resolved.Mode != systemone.ModeCascade || resolved.Zone != (systemone.Zone{Lower: 0.4, Upper: 0.9}) || !resolved.Judge.APIKey.Set() {
		t.Fatalf("%+v %v", resolved, err)
	}
	if _, err := systemone.NewJudge(resolved.Judge, nopMasker{}, nil); err != nil {
		t.Fatal(err) // validation only, no network
	}

	cases := []struct {
		name, key, value string
		semantic         bool
	}{
		{"bad bool", "SYSTEMONE_ENABLED", "perhaps", true},
		{"bad mode", "SYSTEMONE_MODE", "both", true},
		{"cascade without primary", "SYSTEMONE_MODE", "cascade", false},
		{"judge only with primary", "SYSTEMONE_MODE", "judge_only", true},
		{"missing lower", "SYSTEMONE_ZONE_LOWER", "", true},
		{"missing upper", "SYSTEMONE_ZONE_UPPER", "", true},
		{"lower not a number", "SYSTEMONE_ZONE_LOWER", "low", true},
		{"lower above upper", "SYSTEMONE_ZONE_LOWER", "0.95", true},
		{"upper above one", "SYSTEMONE_ZONE_UPPER", "1.5", true},
		{"lower negative", "SYSTEMONE_ZONE_LOWER", "-0.1", true},
		{"nan bound", "SYSTEMONE_ZONE_UPPER", "NaN", true},
		{"bad timeout", "SYSTEMONE_TIMEOUT", "soon", true},
		{"zero timeout", "SYSTEMONE_TIMEOUT", "0s", true},
		{"bad threshold", "SYSTEMONE_THRESHOLD", "high", true},
		{"bad max runes", "SYSTEMONE_MAX_TEXT_RUNES", "-3", true},
		{"key with space", "SYSTEMONE_API_KEY", "has " + envKey, true},
		{"missing key", "SYSTEMONE_API_KEY", "", true},
		{"both key sources", "SYSTEMONE_API_KEY_FILE", "/nonexistent", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearSystemOne(t)
			enableSystemOne(t)
			if tc.value == "" {
				os.Unsetenv(tc.key)
			} else {
				t.Setenv(tc.key, tc.value)
			}
			_, err := Load().SystemOne.Resolve(tc.semantic)
			if err == nil {
				t.Fatal("accepted invalid setting")
			}
			if strings.Contains(err.Error(), envKey) {
				t.Fatalf("error leaks the key: %v", err)
			}
		})
	}

	t.Run("malformed but disabled still fails", func(t *testing.T) {
		clearSystemOne(t)
		t.Setenv("SYSTEMONE_TIMEOUT", "soon")
		if _, err := Load().SystemOne.Resolve(false); err == nil {
			t.Fatal("a mistyped variable must not pass silently")
		}
	})
	t.Run("zero value is disabled", func(t *testing.T) {
		// Configurations built as literals (tests, embedders) leave SystemOne zero.
		if resolved, err := (SystemOne{}).Resolve(true); err != nil || resolved != nil {
			t.Fatalf("zero value must resolve to disabled: %+v %v", resolved, err)
		}
		if _, err := (SystemOne{Enabled: true}).Resolve(true); err == nil {
			t.Fatal("an enabled literal without a mode must fail")
		}
	})
	for _, variable := range []string{"SYSTEMONE_MODE", "SYSTEMONE_QUESTION", "SYSTEMONE_FAILURE_MODE"} {
		t.Run("mistyped "+variable+" while disabled", func(t *testing.T) {
			clearSystemOne(t)
			t.Setenv(variable, "typo")
			if _, err := Load().SystemOne.Resolve(false); err == nil || !strings.Contains(err.Error(), variable) {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("judge only needs no zone", func(t *testing.T) {
		clearSystemOne(t)
		enableSystemOne(t)
		os.Unsetenv("SYSTEMONE_ZONE_LOWER")
		os.Unsetenv("SYSTEMONE_ZONE_UPPER")
		t.Setenv("SYSTEMONE_MODE", "judge_only")
		if resolved, err := Load().SystemOne.Resolve(false); err != nil || resolved.Mode != systemone.ModeJudgeOnly {
			t.Fatal(err)
		}
	})
}

func TestSystemOneKeyFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, tc := range map[string]struct {
		path string
		ok   bool
	}{
		"valid with newline": {write("ok", envKey+"\n"), true},
		"empty":              {write("empty", "\n"), false},
		"two tokens":         {write("two", envKey+" "+envKey), false},
		"too large":          {write("large", strings.Repeat("k", maxKeyFileBytes+1)), false},
		"missing":            {filepath.Join(dir, "missing"), false},
	} {
		t.Run(name, func(t *testing.T) {
			clearSystemOne(t)
			enableSystemOne(t)
			os.Unsetenv("SYSTEMONE_API_KEY")
			t.Setenv("SYSTEMONE_API_KEY_FILE", tc.path)
			resolved, err := Load().SystemOne.Resolve(true)
			if (err == nil) != tc.ok {
				t.Fatalf("got %v", err)
			}
			if err != nil && (strings.Contains(err.Error(), envKey) || strings.Contains(err.Error(), dir)) {
				t.Fatalf("error leaks key or path: %v", err)
			}
			if tc.ok && fmt.Sprint(resolved) != "" && strings.Contains(fmt.Sprintf("%+v", resolved), envKey) {
				t.Fatal("resolved configuration renders the key")
			}
		})
	}
	t.Run("not read while disabled", func(t *testing.T) {
		clearSystemOne(t)
		t.Setenv("SYSTEMONE_API_KEY_FILE", filepath.Join(dir, "missing"))
		if _, err := Load().SystemOne.Resolve(false); err != nil {
			t.Fatal(err)
		}
	})
}

type nopMasker struct{}

func (nopMasker) Mask(_ context.Context, text string) (string, error) { return text, nil }
