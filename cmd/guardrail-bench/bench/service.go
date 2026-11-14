package bench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/g1lom/guardrail-serve/internal/app"
	"github.com/g1lom/guardrail-serve/internal/config"
)

// Bench policies: the deterministic detector alone, and the deterministic
// detector plus the semantic detector, both blocking on both stages. The policy
// engine evaluates every step (no short-circuit), so the union decision is
// BLOCKED when either detector fires and the findings tell which did.
const (
	PolicyRules = "bench-rules"
	PolicyUnion = "bench-union"
)

const benchPolicies = `version: 1
policies:
  - name: bench-rules
    mode: enforce
    stages:
      input:
        - detector: prompt_injection
          action: block
      output:
        - detector: prompt_injection
          action: block
  - name: bench-union
    mode: enforce
    stages:
      input:
        - detector: prompt_injection
          action: block
        - detector: semantic_prompt_injection
          action: block
      output:
        - detector: prompt_injection
          action: block
        - detector: semantic_prompt_injection
          action: block
`

// serviceEnvPrefixes are cleared before each run so that no setting of the
// calling shell leaks into a measured configuration.
var serviceEnvPrefixes = []string{"SEMANTIC_", "SYSTEMONE_", "GUARDRAIL", "HTTP_", "API_", "LITELLM_", "MAX_TEXT_", "SECRET_MASK", "PROJECT_NAME", "LOG_FORMAT"}

// DummyJudgeKey is what the in-process service holds: the real key never
// leaves the loopback proxy.
const DummyJudgeKey = "bench-loopback-placeholder-key"

// Service is the real guardrail-serve handler on a loopback listener.
type Service struct {
	URL    string
	server *http.Server
	done   chan error
}

// StartService writes the bench policies under workDir, sets the run
// environment and serves the handler built by internal/app on 127.0.0.1.
func StartService(ctx context.Context, workDir string, env map[string]string, logOutput io.Writer) (*Service, error) {
	policiesDir := filepath.Join(workDir, "policies")
	if err := os.MkdirAll(policiesDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(policiesDir, "policies.yaml"), []byte(benchPolicies), 0o644); err != nil {
		return nil, err
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		for _, prefix := range serviceEnvPrefixes {
			if strings.HasPrefix(name, prefix) {
				_ = os.Unsetenv(name)
			}
		}
	}
	base := map[string]string{
		"GUARDRAILS_CONFIG_DIR":  policiesDir,
		"LITELLM_DEFAULT_POLICY": PolicyRules,
		"LOG_FORMAT":             "json",
		"API_PORT":               "0",
	}
	for name, value := range env {
		base[name] = value
	}
	for name, value := range base {
		if err := os.Setenv(name, value); err != nil {
			return nil, err
		}
	}
	cfg := config.Load()
	logger := slog.New(slog.NewJSONHandler(logOutput, &slog.HandlerOptions{Level: slog.LevelWarn}))
	server, err := app.NewServerWithLogger(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("build service: %w", err)
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	service := &Service{URL: "http://" + listener.Addr().String(), server: server, done: make(chan error, 1)}
	go func() { service.done <- app.Serve(ctx, server, listener, cfg.Runtime) }()
	if err := waitHealthy(ctx, service.URL+"/health/"); err != nil {
		_ = service.Close()
		return nil, err
	}
	return service, nil
}

// Close shuts the service down.
func (s *Service) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.server.Shutdown(ctx)
	select {
	case serveErr := <-s.done:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && err == nil {
			err = serveErr
		}
	case <-ctx.Done():
	}
	return err
}

func waitHealthy(ctx context.Context, url string) error {
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if response, err := client.Do(request); err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		sleepContext(ctx, 50*time.Millisecond)
	}
	return errors.New("service did not become healthy")
}
