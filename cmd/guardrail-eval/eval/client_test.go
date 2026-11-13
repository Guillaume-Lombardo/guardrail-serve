package eval_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

func newClient(t *testing.T, cfg eval.ClientConfig) *eval.Client {
	t.Helper()
	client, err := eval.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func requestError(t *testing.T, err error) *eval.RequestError {
	t.Helper()
	var reqErr *eval.RequestError
	if !errors.As(err, &reqErr) {
		t.Fatalf("err = %v, want *RequestError", err)
	}
	return reqErr
}

func TestPolicySendsDocumentedRequestAndDecodesFindings(t *testing.T) {
	svc := newFakeService(t)
	svc.Findings["write to zoe@example.fr"] = []string{"detect_pii", "detect_secret"}
	client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL + "/api/", APIKey: "demo-key-1"})

	result, err := client.Policy(context.Background(), "audit", eval.InputResponse, "write to zoe@example.fr")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Detectors, ",") != "detect_pii,detect_secret" || result.Decision != eval.DecisionNone {
		t.Fatalf("result = %+v", result)
	}
	got := svc.Seen()[0]
	if got.Method != http.MethodPost || got.Path != "/api/v1/guardrails/audit" || got.ContentType != "application/json" {
		t.Fatalf("request = %+v", got)
	}
	if got.Authorization != "Bearer demo-key-1" || got.APIKey != "" {
		t.Fatalf("auth headers = %q / %q", got.Authorization, got.APIKey)
	}
	if len(got.Body.Texts) != 1 || got.Body.Texts[0] != "write to zoe@example.fr" || got.Body.InputType != "response" {
		t.Fatalf("body = %+v", got.Body)
	}
}

func TestScanSendsDocumentedRequestWithAPIKeyHeader(t *testing.T) {
	svc := newFakeService(t)
	svc.Scans["/scan/pii|mail zoe@example.fr"] = "GUARDRAIL_INTERVENED"
	client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL, APIKey: "demo-key-2", AuthScheme: eval.AuthAPIKey})

	result, err := client.Scan(context.Background(), "/scan/pii", eval.InputRequest, "mail zoe@example.fr")
	if err != nil || result.Decision != eval.DecisionIntervened {
		t.Fatalf("result = %+v err = %v", result, err)
	}
	got := svc.Seen()[0]
	if got.Path != "/scan/pii" || got.APIKey != "demo-key-2" || got.Authorization != "" || got.Body.InputType != "request" {
		t.Fatalf("request = %+v", got)
	}
}

func TestNoCredentialHeaderWithoutKey(t *testing.T) {
	svc := newFakeService(t)
	client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL})
	if _, err := client.Scan(context.Background(), "/scan/secrets", eval.InputRequest, "x"); err != nil {
		t.Fatal(err)
	}
	if got := svc.Seen()[0]; got.Authorization != "" || got.APIKey != "" {
		t.Fatalf("unexpected credentials: %+v", got)
	}
}

func TestRequestFailuresAreDistinguishedAndSafe(t *testing.T) {
	const secretText = "text-that-must-not-leak"
	const key = "demo-key-3"
	respond := func(status int, body string) func(http.ResponseWriter, *http.Request, received) bool {
		return func(w http.ResponseWriter, _ *http.Request, _ received) bool {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return true
		}
	}
	tests := map[string]struct {
		override func(http.ResponseWriter, *http.Request, received) bool
		call     string
		kind     eval.ErrorKind
		status   int
	}{
		"http 500": {respond(500, `{"detail":"`+secretText+`"}`), "scan", eval.KindHTTPStatus, 500},
		"http 401": {respond(401, `{}`), "policy", eval.KindHTTPStatus, 401},
		"http 422": {respond(422, `{}`), "scan", eval.KindHTTPStatus, 422},
		"redirect not followed": {func(w http.ResponseWriter, r *http.Request, _ received) bool {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return true
		}, "scan", eval.KindHTTPStatus, 302},
		"not json":             {respond(200, `<html>`), "scan", eval.KindInvalidResponse, 0},
		"unknown decision":     {respond(200, `{"decision":"MAYBE"}`), "scan", eval.KindInvalidResponse, 0},
		"missing findings":     {respond(200, `{"decision":"NONE"}`), "policy", eval.KindInvalidResponse, 0},
		"null findings":        {respond(200, `{"decision":"NONE","findings":null}`), "policy", eval.KindInvalidResponse, 0},
		"foreign text index":   {respond(200, `{"decision":"NONE","findings":[{"text_index":1,"detector":"d"}]}`), "policy", eval.KindInvalidResponse, 0},
		"finding no detector":  {respond(200, `{"decision":"NONE","findings":[{"text_index":0}]}`), "policy", eval.KindInvalidResponse, 0},
		"too large":            {respond(200, `{"decision":"NONE","pad":"`+strings.Repeat("x", 600)+`"}`), "scan", eval.KindResponseTooLarge, 200},
		"policy limit block":   {respond(200, `{"decision":"BLOCKED","findings":[]}`), "policy", eval.KindLimitExceeded, 0},
		"scan limit block":     {respond(200, `{"decision":"BLOCKED","metadata":{"guardrail":"max_length"}}`), "scan", eval.KindLimitExceeded, 0},
		"scan no metadata":     {respond(200, `{"decision":"BLOCKED"}`), "scan", eval.KindInvalidResponse, 0},
		"scan empty guardrail": {respond(200, `{"decision":"NONE","metadata":{"guardrail":""}}`), "scan", eval.KindInvalidResponse, 0},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			svc := newFakeService(t)
			svc.Override = tc.override
			client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL, APIKey: key, MaxResponseBytes: 512})
			var err error
			if tc.call == "scan" {
				_, err = client.Scan(context.Background(), "/scan/secrets", eval.InputRequest, secretText)
			} else {
				_, err = client.Policy(context.Background(), "audit", eval.InputRequest, secretText)
			}
			reqErr := requestError(t, err)
			if reqErr.Kind != tc.kind || reqErr.Status != tc.status {
				t.Fatalf("err = %+v, want kind %s status %d", reqErr, tc.kind, tc.status)
			}
			if strings.Contains(reqErr.Error(), secretText) || strings.Contains(reqErr.Error(), key) {
				t.Fatalf("error leaks request or response data: %v", reqErr)
			}
		})
	}
}

func TestBlockedWithFindingsIsADetection(t *testing.T) {
	svc := newFakeService(t)
	svc.Override = func(w http.ResponseWriter, _ *http.Request, _ received) bool {
		_, _ = w.Write([]byte(`{"decision":"BLOCKED","findings":[{"text_index":0,"detector":"prompt_injection"}]}`))
		return true
	}
	result, err := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL}).Policy(context.Background(), "default", eval.InputRequest, "x")
	if err != nil || result.Decision != eval.DecisionBlocked || len(result.Detectors) != 1 {
		t.Fatalf("result = %+v err = %v", result, err)
	}
}

func TestTransportFailures(t *testing.T) {
	t.Run("connection refused", func(t *testing.T) {
		svc := newFakeService(t)
		url := svc.Server.URL
		svc.Server.Close()
		_, err := newClient(t, eval.ClientConfig{BaseURL: url}).Scan(context.Background(), "/scan/pii", eval.InputRequest, "x")
		if reqErr := requestError(t, err); reqErr.Kind != eval.KindTransport || reqErr.Status != 0 {
			t.Fatalf("err = %+v", reqErr)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		svc := newFakeService(t)
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		svc.Override = func(http.ResponseWriter, *http.Request, received) bool { <-release; return true }
		client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL, Timeout: 50 * time.Millisecond})
		_, err := client.Scan(context.Background(), "/scan/pii", eval.InputRequest, "x")
		if reqErr := requestError(t, err); reqErr.Kind != eval.KindTransport || !strings.Contains(reqErr.Message, "timeout") {
			t.Fatalf("err = %+v", reqErr)
		}
	})
	t.Run("canceled", func(t *testing.T) {
		svc := newFakeService(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL}).Scan(ctx, "/scan/pii", eval.InputRequest, "x")
		if reqErr := requestError(t, err); reqErr.Kind != eval.KindTransport || !strings.Contains(reqErr.Message, "canceled") {
			t.Fatalf("err = %+v", reqErr)
		}
	})
}

func TestNewClientValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg  eval.ClientConfig
		want string // empty means valid
	}{
		"relative url":          {eval.ClientConfig{BaseURL: "localhost:8000"}, "absolute"},
		"ftp":                   {eval.ClientConfig{BaseURL: "ftp://example.org"}, "absolute"},
		"credentials in url":    {eval.ClientConfig{BaseURL: "http://user:pw@127.0.0.1:1"}, "credentials"},
		"query in url":          {eval.ClientConfig{BaseURL: "http://127.0.0.1:1/?x=1"}, "query"},
		"bad scheme name":       {eval.ClientConfig{BaseURL: "http://127.0.0.1:1", AuthScheme: "basic"}, "auth scheme"},
		"key with space":        {eval.ClientConfig{BaseURL: "http://127.0.0.1:1", APIKey: "a b"}, "whitespace"},
		"key over remote http":  {eval.ClientConfig{BaseURL: "http://guardrail.example.org", APIKey: "k"}, "plain http"},
		"key over remote http+": {eval.ClientConfig{BaseURL: "http://guardrail.example.org", APIKey: "k", AllowInsecureAuth: true}, ""},
		"key over https":        {eval.ClientConfig{BaseURL: "https://guardrail.example.org/prefix/", APIKey: "k"}, ""},
		"key over loopback":     {eval.ClientConfig{BaseURL: "http://127.0.0.1:8000", APIKey: "k"}, ""},
		"key over localhost":    {eval.ClientConfig{BaseURL: "http://localhost:8000", APIKey: "k"}, ""},
		"key over ipv6 lo":      {eval.ClientConfig{BaseURL: "http://[::1]:8000", APIKey: "k"}, ""},
		"negative timeout":      {eval.ClientConfig{BaseURL: "http://127.0.0.1:1", Timeout: -time.Second}, "positive"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := eval.NewClient(tc.cfg)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
	client := newClient(t, eval.ClientConfig{BaseURL: " https://guardrail.example.org/prefix/ "})
	if client.BaseURL() != "https://guardrail.example.org/prefix" {
		t.Fatalf("base = %s", client.BaseURL())
	}
}

func TestPolicyRejectsInvalidNamesBeforeSending(t *testing.T) {
	svc := newFakeService(t)
	client := newClient(t, eval.ClientConfig{BaseURL: svc.Server.URL})
	for _, name := range []string{"", "../scan", "Default", "a b", "x/y"} {
		if _, err := client.Policy(context.Background(), name, eval.InputRequest, "x"); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
	if len(svc.Seen()) != 0 {
		t.Fatal("requests were sent")
	}
}

func TestParseEnums(t *testing.T) {
	if m, err := eval.ParseMode("enforce"); err != nil || m != eval.ModeEnforce {
		t.Fatal(m, err)
	}
	if _, err := eval.ParseMode("Annotate"); err == nil {
		t.Fatal("mode is case sensitive")
	}
	if f, err := eval.ParseFormat(""); err != nil || f != eval.FormatText {
		t.Fatal(f, err)
	}
	if _, err := eval.ParseFormat("yaml"); err == nil {
		t.Fatal("yaml accepted")
	}
	if s, err := eval.ParseAuthScheme(""); err != nil || s != eval.AuthBearer {
		t.Fatal(s, err)
	}
	if i, err := eval.ParseInputType(""); err != nil || i != eval.InputRequest {
		t.Fatal(i, err)
	}
	if _, err := json.Marshal(eval.ModeAnnotate); err != nil {
		t.Fatal(err)
	}
}

// A server that answers with garbage and echoes the credential must not get it
// copied into the error, which ends up in reports.
func TestMalformedHTTPResponseDoesNotEchoRemoteData(t *testing.T) {
	const key = "echoed-key-value-123"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.CopyN(io.Discard, conn, 1)
		_, _ = conn.Write([]byte("NOT-HTTP " + key + "\r\n\r\n"))
	}()
	client := newClient(t, eval.ClientConfig{BaseURL: "http://" + listener.Addr().String(), APIKey: key})
	_, err = client.Scan(context.Background(), "/scan/secrets", eval.InputRequest, "x")
	reqErr := requestError(t, err)
	if reqErr.Kind != eval.KindTransport || strings.Contains(reqErr.Error(), key) {
		t.Fatalf("err = %v", reqErr)
	}
}

func TestTLSVerificationFailureIsNamed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	client := newClient(t, eval.ClientConfig{BaseURL: server.URL})
	_, err := client.Scan(context.Background(), "/scan/secrets", eval.InputRequest, "x")
	reqErr := requestError(t, err)
	if reqErr.Kind != eval.KindTransport || !strings.Contains(reqErr.Message, "certificate") {
		t.Fatalf("err = %+v", reqErr)
	}
}
