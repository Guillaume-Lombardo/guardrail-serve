package main

import (
	"log"

	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
)

func main() {
	cfg := config.Load()
	server, err := app.NewServer(cfg)
	if err != nil {
		log.Fatalf("build server: %v", err)
	}

	log.Printf("guardrail-serve listening on %s", cfg.ListenAddr())
	if err := server.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
		log.Fatalf("serve http: %v", err)
	}
}
