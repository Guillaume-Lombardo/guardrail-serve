// Command guardrail-eval evaluates a running guardrail-serve against labelled
// corpora through its public HTTP API. It imports no service package.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := eval.Main(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
