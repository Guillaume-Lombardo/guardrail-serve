package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		logger.Error("listen http", "error", err)
		os.Exit(1)
	}
	logger.Info("guardrail-serve listening", "listen_addr", cfg.ListenAddr(), "log_format", cfg.LogFormat)
	if err := app.Serve(ctx, server, listener, cfg.Runtime); err != nil {
		logger.Error("serve http", "error", err)
		os.Exit(1)
	}
}
