package main

import (
	"os"

	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
	"github.com/g1lom/guardrail-serve/internal/observability"
)

func main() {
	cfg := config.Load()
	logger := observability.NewDefaultLogger(cfg.LogFormat, cfg.ProjectName)
	server, err := app.NewServerWithLogger(cfg, logger)
	if err != nil {
		logger.Error("build server", "error", err)
		os.Exit(1)
	}

	logger.Info("guardrail-serve listening", "listen_addr", cfg.ListenAddr(), "log_format", cfg.LogFormat)
	if err := server.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
		logger.Error("serve http", "error", err)
		os.Exit(1)
	}
}
