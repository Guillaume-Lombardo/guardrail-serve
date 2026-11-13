package semanticsidecar_test

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// sidecarDir is deploy/semantic-sidecar relative to this package.
var sidecarDir = filepath.Join("..", "..", "..", "deploy", "semantic-sidecar")

func python(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available: sidecar server tests skipped")
	}
	return path
}

// startSidecar runs the real sidecar HTTP server (the production code path)
// with a deterministic fake backend: no model, no torch, no network access
// beyond loopback. It returns the base URL.
func startSidecar(t *testing.T, env map[string]string) string {
	t.Helper()
	cmd := exec.Command(python(t), "-I", filepath.Join(sidecarDir, "tests", "run_fake_server.py"))
	cmd.Env = []string{"SIDECAR_HOST=127.0.0.1", "SIDECAR_PORT=0"}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr lockedBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("sidecar log:\n%s", stderr.String())
		}
	})

	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		lines <- strings.TrimSpace(line)
	}()
	var port int
	select {
	case line := <-lines:
		if _, err := fmt.Sscanf(line, "LISTENING %d", &port); err != nil {
			t.Fatalf("unexpected sidecar banner %q", line)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("sidecar did not start")
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/readyz", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz status %d", resp.StatusCode)
	}
	return base
}

// lockedBuffer collects the sidecar's log so it is shown only when a test fails.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
