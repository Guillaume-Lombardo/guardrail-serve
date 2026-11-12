package app_test

import (
	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
	"testing"
	"time"
)

func TestRuntimeServerTimeoutWiring(t *testing.T) {
	cfg := config.Load()
	cfg.Runtime = config.Runtime{ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 4 * time.Second}
	s, err := app.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.ReadHeaderTimeout != time.Second || s.ReadTimeout != 2*time.Second || s.WriteTimeout != 3*time.Second || s.IdleTimeout != 4*time.Second {
		t.Fatal("timeouts not wired")
	}
	cfg.Runtime.ReadTimeout = -1
	if _, err := app.NewServer(cfg); err == nil {
		t.Fatal("invalid runtime accepted")
	}
}
