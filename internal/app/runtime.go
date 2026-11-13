package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/g1lom/guardrail-serve/internal/config"
)

func runtimeHandler(cfg config.Config, next http.Handler) http.Handler {
	cfg.Runtime = cfg.Runtime.Defaults()
	slots := make(chan struct{}, cfg.Runtime.MaxConcurrentRequests)
	keys := make([][sha256.Size]byte, len(cfg.Runtime.APIKeys))
	for i, key := range cfg.Runtime.APIKeys {
		keys[i] = sha256.Sum256([]byte(key))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		health := r.Method == http.MethodGet && r.URL.Path == cfg.APIPrefix+"/health/"
		if len(keys) > 0 && !health {
			token, valid := requestKey(r)
			digest := sha256.Sum256([]byte(token))
			match := 0
			for _, key := range keys {
				match |= subtle.ConstantTimeCompare(digest[:], key[:])
			}
			if !valid || match != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				runtimeError(w, http.StatusUnauthorized, "Unauthorized.")
				return
			}
		}
		// Health has no body to parse and must remain available under saturation.
		if health {
			next.ServeHTTP(w, r)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "1")
			runtimeError(w, http.StatusServiceUnavailable, "Service busy.")
			return
		}
		if r.ContentLength > cfg.Runtime.MaxBodyBytes {
			runtimeError(w, http.StatusRequestEntityTooLarge, "Request body too large.")
			return
		}
		if r.Body != nil {
			// Read before dispatch so decoder errors cannot mask the transport limit.
			defer r.Body.Close()
			body, err := io.ReadAll(io.LimitReader(r.Body, cfg.Runtime.MaxBodyBytes+1))
			if int64(len(body)) > cfg.Runtime.MaxBodyBytes {
				runtimeError(w, http.StatusRequestEntityTooLarge, "Request body too large.")
				return
			}
			if err != nil {
				runtimeError(w, http.StatusBadRequest, "Cannot read request body.")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		next.ServeHTTP(w, r)
	})
}

func requestKey(r *http.Request) (string, bool) {
	auth, api := r.Header.Values("Authorization"), r.Header.Values("X-API-Key")
	if len(auth)+len(api) != 1 {
		return "", false
	}
	if len(api) == 1 {
		return api[0], api[0] != ""
	}
	scheme, token, ok := strings.Cut(auth[0], " ")
	return token, ok && strings.EqualFold(scheme, "Bearer") && token != "" && !strings.ContainsAny(token, " \t\r\n")
}

func runtimeError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"detail":"`+detail+`"}`+"\n")
}

// Serve runs until cancellation, then drains in-flight requests within the configured deadline.
// The caller owns signal registration and the listener is owned by the server.
func Serve(ctx context.Context, server *http.Server, listener net.Listener, runtime config.Runtime) error {
	runtime = runtime.Defaults()
	if err := runtime.Validate(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), runtime.ShutdownTimeout)
		defer cancel()
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			_ = server.Close()
		}
		<-done
		return err
	}
}
