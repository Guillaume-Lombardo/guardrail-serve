package main

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRuntimeSignalHelper(t *testing.T) {
	if os.Getenv("RUNTIME_SIGNAL_HELPER") == "1" {
		main()
		os.Exit(0)
	}
}

func TestRuntimeSignalsExitCleanly(t *testing.T) {
	for _, sig := range []os.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRuntimeSignalHelper$")
			cmd.Env = append(os.Environ(), "RUNTIME_SIGNAL_HELPER=1", "API_PORT=0", "HTTP_SHUTDOWN_TIMEOUT=1s", "GUARDRAIL_API_KEYS=")
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill() }()
			ready := make(chan bool, 1)
			go func() {
				scanner := bufio.NewScanner(out)
				for scanner.Scan() {
					if strings.Contains(scanner.Text(), "guardrail-serve listening") {
						ready <- true
						return
					}
				}
				ready <- false
			}()
			select {
			case ok := <-ready:
				if !ok {
					t.Fatal("not ready")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("startup timed out")
			}
			if err = cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err = <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("signal shutdown timed out")
			}
		})
	}
}
