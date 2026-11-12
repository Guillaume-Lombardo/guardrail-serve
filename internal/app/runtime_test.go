package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g1lom/guardrail-serve/internal/config"
)

func TestRuntimeBodyLimitUnknownLength(t *testing.T) {
	for _, tc := range []struct {
		body   string
		status int
	}{{"1234", 204}, {"12345", 413}} {
		h := runtimeHandler(config.Config{Runtime: config.Runtime{MaxBodyBytes: 4}}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			if string(b) != tc.body {
				t.Error("body changed")
			}
			w.WriteHeader(204)
		}))
		r := httptest.NewRequest("POST", "/", strings.NewReader(tc.body))
		r.ContentLength = -1
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("got %d want %d", w.Code, tc.status)
		}
	}
}

func TestServeDrainsOrBoundsShutdown(t *testing.T) {
	for _, bounded := range []bool{false, true} {
		t.Run(map[bool]string{false: "drain", true: "deadline"}[bounded], func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				select {
				case <-release:
				case <-r.Context().Done():
				}
				_, _ = w.Write([]byte("done"))
			})}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- Serve(ctx, srv, l, config.Runtime{ShutdownTimeout: 100 * time.Millisecond}) }()
			response := make(chan error, 1)
			go func() {
				res, e := http.Get("http://" + l.Addr().String())
				if e == nil {
					_, e = io.ReadAll(res.Body)
					res.Body.Close()
				}
				response <- e
			}()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("request did not start")
			}
			cancel()
			if !bounded { // release after cancellation; Shutdown must wait for the handler.
				select {
				case e := <-done:
					t.Fatalf("returned before drain: %v", e)
				default:
				}
				release <- struct{}{}
			}
			select {
			case err := <-done:
				if bounded && err == nil {
					t.Fatal("expected deadline")
				}
				if !bounded && err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("shutdown unbounded")
			}
			<-response
		})
	}
}

func TestRuntimeNetworkReadDeadlines(t *testing.T) {
	for _, header := range []bool{true, false} {
		t.Run(map[bool]string{true: "headers", false: "body"}[header], func(t *testing.T) {
			cfg := config.Load()
			cfg.Runtime.ReadHeaderTimeout = 50 * time.Millisecond
			cfg.Runtime.ReadTimeout = 100 * time.Millisecond
			srv, err := NewServer(cfg)
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
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			request := "POST /scan/secrets HTTP/1.1\r\nHost: localhost\r\n"
			if !header {
				request += "Content-Length: 100\r\n\r\nx"
			}
			if _, err = io.WriteString(conn, request); err != nil {
				t.Fatal(err)
			}
			_, err = io.ReadAll(conn)
			if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("server did not enforce read deadline")
			}
		})
	}
}
