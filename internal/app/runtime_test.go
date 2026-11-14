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

// TestRuntimeDeadlineStartsOnArrival sends the body slowly to a real server
// configured like NewServer: the request deadline must already have passed at
// dispatch, so no detector call can start after the write deadline.
func TestRuntimeDeadlineStartsOnArrival(t *testing.T) {
	cfg := config.Config{Runtime: config.Runtime{MaxBodyBytes: 64, WriteTimeout: 200 * time.Millisecond, ReadTimeout: 5 * time.Second}}
	dispatched := make(chan error, 1)
	srv := httptest.NewUnstartedServer(runtimeHandler(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dispatched <- r.Context().Err()
		w.WriteHeader(204)
	})))
	srv.Config.ReadTimeout, srv.Config.WriteTimeout = cfg.Runtime.ReadTimeout, cfg.Runtime.WriteTimeout
	srv.Start()
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "POST /scan HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nab"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond) // body completes after the write deadline
	if _, err := io.WriteString(conn, "cd"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-dispatched:
		if err != context.DeadlineExceeded {
			t.Fatalf("dispatched with live context after the write deadline: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler not dispatched")
	}
}
