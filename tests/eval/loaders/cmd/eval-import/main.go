// Command eval-import converts a public dataset (BIPIA, AgentDojo, Presidio)
// into a guardrail-eval corpus. See tests/eval/README.md.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/g1lom/guardrail-serve/tests/eval/loaders"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := loaders.Main(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
