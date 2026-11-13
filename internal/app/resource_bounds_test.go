package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g1lom/guardrail-serve/internal/config"
)

type forbiddenBody struct{ t *testing.T }

func (b forbiddenBody) Read([]byte) (int, error) {
	b.t.Error("body read before admission")
	return 0, io.EOF
}
func (b forbiddenBody) Close() error { return nil }

func TestRuntimeAdmission(t *testing.T) {
	t.Setenv("HTTP_MAX_CONCURRENT_REQUESTS", "1")
	cfg := config.Load()
	cfg.Runtime.APIKeys = []string{"key"}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := runtimeHandler(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			close(started)
			<-release
		}
		w.WriteHeader(204)
	}))
	go func() {
		defer close(done)
		r := httptest.NewRequest("POST", "/hold", nil)
		r.Header.Set("X-API-Key", "key")
		h.ServeHTTP(httptest.NewRecorder(), r)
	}()
	<-started
	defer func() { close(release); <-done }()
	for _, tc := range []struct {
		path, key string
		status    int
	}{{"/scan/secrets", "key", 503}, {"/scan/secrets", "", 401}, {"/health/", "", 204}} {
		r := httptest.NewRequest("GET", tc.path, nil)
		if tc.path != "/health/" {
			r.Body = forbiddenBody{t}
		}
		if tc.key != "" {
			r.Header.Set("X-API-Key", tc.key)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Errorf("%s: got %d want %d", tc.path, w.Code, tc.status)
		}
		if tc.status == 503 && (w.Header().Get("Retry-After") != "1" || w.Body.String() != "{\"detail\":\"Service busy.\"}\n") {
			t.Errorf("unstable overload response: %v %s", w.Header(), w.Body)
		}
	}
}

func TestRuntimeAdmissionRelease(t *testing.T) {
	for _, mode := range []string{"normal", "panic", "cancel", "oversize", "read-error"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("HTTP_MAX_CONCURRENT_REQUESTS", "1")
			cfg := config.Load()
			cfg.Runtime.MaxBodyBytes = 4
			calls := 0
			h := runtimeHandler(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 1 && mode == "panic" {
					panic("test")
				}
				if mode == "cancel" && calls == 1 {
					<-r.Context().Done()
				}
				w.WriteHeader(204)
			}))
			r := httptest.NewRequest("POST", "/", nil)
			if mode == "cancel" {
				ctx, cancel := context.WithCancel(r.Context())
				cancel()
				r = r.WithContext(ctx)
			}
			if mode == "oversize" {
				r.ContentLength = 5
			}
			if mode == "read-error" {
				r.Body = errorBody{}
			}
			func() {
				defer func() {
					v := recover()
					if mode == "panic" && v == nil {
						t.Error("panic swallowed")
					}
				}()
				h.ServeHTTP(httptest.NewRecorder(), r)
			}()
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
			if w.Code != 204 {
				t.Fatalf("slot leaked: %d", w.Code)
			}
		})
	}
}

type errorBody struct{}

func (errorBody) Read([]byte) (int, error) { return 0, fmt.Errorf("read failed") }
func (errorBody) Close() error             { return nil }

func TestRuntimeNetworkHeaderBound(t *testing.T) {
	srv, err := NewServer(config.Load())
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	defer func() { srv.Close(); <-done }()
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = fmt.Fprintf(conn, "GET /health/ HTTP/1.1\r\nHost: localhost\r\nUser-Agent: %s\r\n\r\n", strings.Repeat("x", 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 431 {
		t.Fatalf("got %d want 431", res.StatusCode)
	}
}

func TestMetricsRuntimeAdmissionAndPrefix(t *testing.T) {
	cfg := config.Load()
	cfg.APIPrefix = "/api"
	cfg.Runtime.APIKeys = []string{"fixture"}
	handler, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, key string
		status    int
	}{
		{"/api/metrics", "", 401}, {"/api/metrics", "fixture", 200}, {"/api/health/", "", 200},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		if tc.key != "" {
			r.Header.Set("X-API-Key", tc.key)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s: %d", tc.path, w.Code)
		}
	}
	cfg.APIPrefix = ""
	cfg.Runtime.MaxConcurrentRequests = 1
	started, release := make(chan struct{}), make(chan struct{})
	h := runtimeHandler(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			close(started)
			<-release
		}
		w.WriteHeader(204)
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := httptest.NewRequest("GET", "/hold", nil)
		r.Header.Set("X-API-Key", "fixture")
		h.ServeHTTP(httptest.NewRecorder(), r)
	}()
	<-started
	defer func() { close(release); <-done }()
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Header.Set("X-API-Key", "fixture")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("scrape bypassed admission: %d", w.Code)
	}
}
