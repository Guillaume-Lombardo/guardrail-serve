package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Runtime contains transport protections. Zero values use safe defaults.
type Runtime struct {
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxBodyBytes      int64
	APIKeys           []string
}

func loadRuntime() Runtime {
	r := Runtime{
		ReadHeaderTimeout: runtimeDuration("HTTP_READ_HEADER_TIMEOUT", 5*time.Second),
		ReadTimeout:       runtimeDuration("HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:      runtimeDuration("HTTP_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:       runtimeDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
		ShutdownTimeout:   runtimeDuration("HTTP_SHUTDOWN_TIMEOUT", 10*time.Second),
		MaxBodyBytes:      1 << 20,
	}
	if v := strings.TrimSpace(os.Getenv("HTTP_MAX_BODY_BYTES")); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			n = -1
		}
		r.MaxBodyBytes = n
	}
	if v := strings.TrimSpace(os.Getenv("GUARDRAIL_API_KEYS")); v != "" {
		r.APIKeys = strings.Split(v, ",")
		for i := range r.APIKeys {
			r.APIKeys[i] = strings.TrimSpace(r.APIKeys[i])
		}
	}
	return r
}

func runtimeDuration(name string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return -1
	}
	return d
}

func (r Runtime) Defaults() Runtime {
	if r.ReadHeaderTimeout == 0 {
		r.ReadHeaderTimeout = 5 * time.Second
	}
	if r.ReadTimeout == 0 {
		r.ReadTimeout = 15 * time.Second
	}
	if r.WriteTimeout == 0 {
		r.WriteTimeout = 30 * time.Second
	}
	if r.IdleTimeout == 0 {
		r.IdleTimeout = 60 * time.Second
	}
	if r.ShutdownTimeout == 0 {
		r.ShutdownTimeout = 10 * time.Second
	}
	if r.MaxBodyBytes == 0 {
		r.MaxBodyBytes = 1 << 20
	}
	return r
}

func (r Runtime) Validate() error {
	for _, d := range []struct {
		name  string
		value time.Duration
	}{
		{"HTTP_READ_HEADER_TIMEOUT", r.ReadHeaderTimeout}, {"HTTP_READ_TIMEOUT", r.ReadTimeout},
		{"HTTP_WRITE_TIMEOUT", r.WriteTimeout}, {"HTTP_IDLE_TIMEOUT", r.IdleTimeout}, {"HTTP_SHUTDOWN_TIMEOUT", r.ShutdownTimeout},
	} {
		if d.value <= 0 {
			return fmt.Errorf("%s must be a positive duration", d.name)
		}
	}
	if r.MaxBodyBytes <= 0 || r.MaxBodyBytes > 1<<20 {
		return fmt.Errorf("HTTP_MAX_BODY_BYTES must be between 1 and 1048576")
	}
	for _, key := range r.APIKeys {
		if key == "" || strings.ContainsAny(key, " \t\r\n") {
			return fmt.Errorf("GUARDRAIL_API_KEYS must contain non-empty keys without whitespace")
		}
	}
	return nil
}
