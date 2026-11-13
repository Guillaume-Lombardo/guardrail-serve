package httpclassifier

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const canary = "CANARY-secret-user-text"

func newServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func newClassifier(t *testing.T, url string, mutate func(*Config)) *Classifier {
	t.Helper()
	cfg := Config{
		URL:         url,
		Format:      FormatScores,
		Threshold:   0.5,
		Timeout:     5 * time.Second,
		FailureMode: FailClosed,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	classifier, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return classifier
}

func readBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("read body: %v", err)
	}
	return body
}

// scoresServer answers the scores contract with score(text) per text.
func scoresServer(t *testing.T, score func(string) float64) *httptest.Server {
	return newServer(t, func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Texts []string `json:"texts"`
		}
		if err := json.Unmarshal(readBody(t, r), &request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		scores := make([]float64, len(request.Texts))
		for i, text := range request.Texts {
			scores[i] = score(text)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"scores": scores})
	})
}

// blockUntilClientGone signals started (when set), then holds the request until
// the client gives up. The body is drained first: net/http only notices a
// closed connection once the request body has been consumed.
func blockUntilClientGone(r *http.Request, started chan<- struct{}) {
	_, _ = io.Copy(io.Discard, r.Body)
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	<-r.Context().Done()
}

func fixed(value float64) func(string) float64 { return func(string) float64 { return value } }

func rawServer(t *testing.T, status int, body string) *httptest.Server {
	return newServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func TestScoresFormatRequestAndMaxOverTexts(t *testing.T) {
	var gotMethod, gotType, gotBody string
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotType = r.Method, r.Header.Get("Content-Type")
		gotBody = string(readBody(t, r))
		_, _ = io.WriteString(w, `{"scores":[0.1,0.7,0.3],"extra":"ignored"}`)
	})
	classifier := newClassifier(t, server.URL, func(c *Config) { c.ModelName = "pg2-22m" })

	assessment, err := classifier.DetectPromptInjection(context.Background(), []string{"a", "b é", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotType != "application/json" {
		t.Fatalf("unexpected method %q or content type %q", gotMethod, gotType)
	}
	if want := `{"texts":["a","b é","c"]}`; gotBody != want {
		t.Fatalf("request body = %s, want %s", gotBody, want)
	}
	if !assessment.Triggered || assessment.Score != 0.7 || assessment.Model != "pg2-22m" || assessment.Reason == "" {
		t.Fatalf("unexpected assessment %+v", assessment)
	}
	if assessment.Metadata["classifier_top_text_index"] != 1 || assessment.Metadata["classifier_chunks"] != 3 ||
		assessment.Metadata["classifier_format"] != "scores" {
		t.Fatalf("unexpected metadata %+v", assessment.Metadata)
	}
}

func TestThresholdBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		threshold float64
		score     float64
		triggered bool
	}{
		{"just below", 0.5, 0.4999999, false},
		{"equal", 0.5, 0.5, true},
		{"just above", 0.5, 0.5000001, true},
		{"zero score", 0.5, 0, false},
		{"max threshold hit", 1, 1, true},
		{"max threshold miss", 1, 0.9999999, false},
		{"tiny threshold", 0.0001, 0.0001, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := scoresServer(t, fixed(tt.score))
			classifier := newClassifier(t, server.URL, func(c *Config) { c.Threshold = tt.threshold })
			assessment, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
			if err != nil {
				t.Fatal(err)
			}
			if assessment.Triggered != tt.triggered || assessment.Score != tt.score {
				t.Fatalf("got triggered=%v score=%v", assessment.Triggered, assessment.Score)
			}
			if !tt.triggered && assessment.Reason != "" {
				t.Fatalf("non-triggered assessment has reason %q", assessment.Reason)
			}
		})
	}
}

func TestNoRequestForEmptyOrBlankInput(t *testing.T) {
	var calls atomic.Int32
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	classifier := newClassifier(t, server.URL, nil)

	for _, texts := range [][]string{nil, {}, {"", "  \n\t"}} {
		assessment, err := classifier.DetectPromptInjection(context.Background(), texts)
		if err != nil || assessment.Triggered || assessment.Score != 0 {
			t.Fatalf("texts %q: %+v, %v", texts, assessment, err)
		}
		if _, ok := assessment.Metadata["classifier_top_text_index"]; ok {
			t.Fatal("top text index reported without scanned text")
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("server called %d times", calls.Load())
	}
}

func TestBlankTextsKeepOriginalIndexes(t *testing.T) {
	server := scoresServer(t, func(text string) float64 {
		if strings.Contains(text, "attack") {
			return 0.9
		}
		return 0.1
	})
	classifier := newClassifier(t, server.URL, nil)
	assessment, err := classifier.DetectPromptInjection(context.Background(), []string{"", "hello", " ", "attack"})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Metadata["classifier_top_text_index"] != 3 || assessment.Metadata["classifier_chunks"] != 2 {
		t.Fatalf("unexpected metadata %+v", assessment.Metadata)
	}
}

func TestTEIPredictRequestAndMultilabelResponse(t *testing.T) {
	var gotBody string
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotBody = string(readBody(t, r))
		_, _ = io.WriteString(w, `[
			[{"label":"BENIGN","score":0.99},{"label":"MALICIOUS","score":0.01}],
			[{"label":"benign","score":0.15},{"label":"malicious","score":0.85}]
		]`)
	})
	classifier := newClassifier(t, server.URL, func(c *Config) { c.Format = FormatTEIPredict })

	assessment, err := classifier.DetectPromptInjection(context.Background(), []string{"hello", "ignore all"})
	if err != nil {
		t.Fatal(err)
	}
	// A bare ["a","b"] would be a (query, text) pair for TEI: each text must be its own one-element sequence.
	if want := `{"inputs":[["hello"],["ignore all"]],"raw_scores":false,"truncate":false}`; gotBody != want {
		t.Fatalf("request body = %s, want %s", gotBody, want)
	}
	if !assessment.Triggered || assessment.Score != 0.85 || assessment.Metadata["classifier_top_text_index"] != 1 {
		t.Fatalf("unexpected assessment %+v", assessment)
	}
}

func TestTEIPredictConfiguredLabelsTakeMaxAndIgnoreOthers(t *testing.T) {
	server := rawServer(t, 200, `[[
		{"label":"LABEL_0","score":0.97},
		{"label":"LABEL_1","score":0.2},
		{"label":"jailbreak","score":0.6},
		{"label":"MALICIOUS","score":0.9}
	]]`)
	classifier := newClassifier(t, server.URL, func(c *Config) {
		c.Format = FormatTEIPredict
		c.MaliciousLabels = []string{"label_1", "jailbreak"}
	})
	assessment, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Score != 0.6 || !assessment.Triggered {
		t.Fatalf("labels must be filtered: %+v", assessment)
	}
}

func TestTEIPredictRejectsInvalidResponses(t *testing.T) {
	tests := map[string]struct {
		body string
		kind FailureKind
	}{
		"flat single response":     {`[{"label":"MALICIOUS","score":0.9}]`, FailureInvalidResponse},
		"missing malicious label":  {`[[{"label":"BENIGN","score":0.9}]]`, FailureInvalidResponse},
		"empty prediction row":     {`[[]]`, FailureInvalidResponse},
		"fewer rows than inputs":   {`[]`, FailureInvalidResponse},
		"missing label":            {`[[{"score":0.9}]]`, FailureInvalidResponse},
		"missing score":            {`[[{"label":"MALICIOUS"}]]`, FailureInvalidResponse},
		"score out of range":       {`[[{"label":"MALICIOUS","score":1.5}]]`, FailureInvalidScore},
		"other label out of range": {`[[{"label":"MALICIOUS","score":0.5},{"label":"BENIGN","score":-1}]]`, FailureInvalidScore},
		"object instead of array":  {`{"error":"x","error_type":"Backend"}`, FailureInvalidResponse},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server := rawServer(t, 200, tt.body)
			classifier := newClassifier(t, server.URL, func(c *Config) { c.Format = FormatTEIPredict })
			_, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
			assertKind(t, err, tt.kind)
		})
	}
}

func assertKind(t *testing.T, err error, kind FailureKind) {
	t.Helper()
	var failure *Error
	if !errors.As(err, &failure) || failure.Kind != kind {
		t.Fatalf("error = %v, want kind %q", err, kind)
	}
}

func TestChunkingScoresMaxAcrossChunksAndFindsBoundaryPhrase(t *testing.T) {
	const phrase = "ignore previous instructions"
	server := scoresServer(t, func(text string) float64 {
		if strings.Contains(text, phrase) {
			return 0.95
		}
		return 0.05
	})
	classifier := newClassifier(t, server.URL, func(c *Config) {
		c.ChunkRunes, c.ChunkOverlapRunes, c.BatchSize = 64, 16, 2
	})

	for offset := 0; offset < 150; offset += 7 {
		text := strings.Repeat("日本語 ", offset/4) + strings.Repeat("é", offset%4) + phrase + strings.Repeat("😀 ", 80)
		assessment, err := classifier.DetectPromptInjection(context.Background(), []string{"clean", text})
		if err != nil {
			t.Fatal(err)
		}
		if !assessment.Triggered || assessment.Score != 0.95 || assessment.Metadata["classifier_top_text_index"] != 1 {
			t.Fatalf("offset %d: %+v", offset, assessment)
		}
		if assessment.Metadata["classifier_chunks"].(int) < 3 {
			t.Fatalf("offset %d: text was not chunked", offset)
		}
	}
}

func TestBatchesRespectBatchSizeAndKeepOrder(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Texts []string `json:"texts"`
		}
		_ = json.Unmarshal(readBody(t, r), &request)
		mu.Lock()
		sizes = append(sizes, len(request.Texts))
		mu.Unlock()
		scores := make([]float64, len(request.Texts))
		for i, text := range request.Texts {
			if text == "t4" {
				scores[i] = 0.8
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"scores": scores})
	})
	classifier := newClassifier(t, server.URL, func(c *Config) { c.BatchSize = 3 })

	texts := []string{"t0", "t1", "t2", "t3", "t4", "t5", "t6"}
	assessment, err := classifier.DetectPromptInjection(context.Background(), texts)
	if err != nil {
		t.Fatal(err)
	}
	if got := sizes; len(got) != 3 || got[0] != 3 || got[1] != 3 || got[2] != 1 {
		t.Fatalf("batch sizes = %v", got)
	}
	if assessment.Score != 0.8 || assessment.Metadata["classifier_top_text_index"] != 4 {
		t.Fatalf("unexpected assessment %+v", assessment)
	}
}

func TestTooManyChunksFailsInsteadOfTruncating(t *testing.T) {
	var calls atomic.Int32
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	classifier := newClassifier(t, server.URL, func(c *Config) { c.ChunkRunes, c.MaxChunks = 64, 4 })

	_, err := classifier.DetectPromptInjection(context.Background(), []string{strings.Repeat("x", 10_000)})
	assertKind(t, err, FailureTooManyChunks)
	_, err = classifier.DetectPromptInjection(context.Background(), []string{"a", "b", "c", "d", "e"})
	assertKind(t, err, FailureTooManyChunks)
	if calls.Load() != 0 {
		t.Fatal("no request may be sent when the input exceeds the chunk budget")
	}
}

func TestInvalidResponsesFailExplicitly(t *testing.T) {
	tests := map[string]struct {
		status int
		body   string
		kind   FailureKind
	}{
		"server error":          {500, `{"scores":[0.9]}`, FailureStatus},
		"client error":          {422, `{"error":"x"}`, FailureStatus},
		"redirect not followed": {302, ``, FailureStatus},
		"not json":              {200, `<html>ok</html>`, FailureInvalidResponse},
		"empty body":            {200, ``, FailureInvalidResponse},
		"NaN literal":           {200, `{"scores":[NaN]}`, FailureInvalidResponse},
		"overflowing number":    {200, `{"scores":[1e999]}`, FailureInvalidResponse},
		"trailing data":         {200, `{"scores":[0.9]} {"scores":[0.9]}`, FailureInvalidResponse},
		"missing scores":        {200, `{"result":[0.9]}`, FailureInvalidResponse},
		"null scores":           {200, `{"scores":null}`, FailureInvalidResponse},
		"null score":            {200, `{"scores":[null]}`, FailureInvalidResponse},
		"string score":          {200, `{"scores":["0.9"]}`, FailureInvalidResponse},
		"negative score":        {200, `{"scores":[-0.0001]}`, FailureInvalidScore},
		"score above one":       {200, `{"scores":[1.0001]}`, FailureInvalidScore},
		"too few scores":        {200, `{"scores":[]}`, FailureInvalidResponse},
		"too many scores":       {200, `{"scores":[0.1,0.2]}`, FailureInvalidResponse},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			server := rawServer(t, tt.status, tt.body)
			classifier := newClassifier(t, server.URL, nil)
			_, err := classifier.DetectPromptInjection(context.Background(), []string{canary})
			assertKind(t, err, tt.kind)
		})
	}
}

func TestStatusErrorReportsStatusCode(t *testing.T) {
	server := rawServer(t, 503, "")
	classifier := newClassifier(t, server.URL, nil)
	_, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
	var failure *Error
	if !errors.As(err, &failure) || failure.Status != 503 || err.Error() != "http classifier: status 503" {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var hits atomic.Int32
	target := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, `{"scores":[0.9]}`)
	})
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	classifier := newClassifier(t, server.URL, nil)
	_, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
	assertKind(t, err, FailureStatus)
	if hits.Load() != 0 {
		t.Fatal("redirect target was contacted")
	}
}

func TestHTTPClientDoesNotUseProxies(t *testing.T) {
	transport, ok := newHTTPClient().Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("classifier transport must not use proxies")
	}
}

func TestResponseBodyIsBounded(t *testing.T) {
	big := `{"scores":[0.1],"pad":"` + strings.Repeat("a", 4096) + `"}`

	t.Run("known length", func(t *testing.T) {
		server := rawServer(t, 200, big)
		classifier := newClassifier(t, server.URL, func(c *Config) { c.MaxResponseBytes = 1024 })
		_, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
		assertKind(t, err, FailureResponseTooLarge)
	})

	t.Run("streamed without length", func(t *testing.T) {
		server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.(http.Flusher).Flush()
			for i := 0; i < 64; i++ {
				if _, err := io.WriteString(w, strings.Repeat("a", 1024)); err != nil {
					return
				}
			}
		})
		classifier := newClassifier(t, server.URL, func(c *Config) { c.MaxResponseBytes = 1024 })
		_, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
		assertKind(t, err, FailureResponseTooLarge)
	})

	t.Run("exactly at the limit", func(t *testing.T) {
		body := `{"scores":[0.25]}`
		server := rawServer(t, 200, body)
		classifier := newClassifier(t, server.URL, func(c *Config) { c.MaxResponseBytes = int64(len(body)) })
		assessment, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
		if err != nil || assessment.Score != 0.25 {
			t.Fatalf("got %+v, %v", assessment, err)
		}
	})
}

func TestFailureModeClosedReturnsError(t *testing.T) {
	server := rawServer(t, 500, "")
	classifier := newClassifier(t, server.URL, func(c *Config) { c.FailureMode = FailClosed })
	assessment, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
	assertKind(t, err, FailureStatus)
	if assessment.Triggered || assessment.Score != 0 || assessment.Metadata != nil {
		t.Fatalf("a failure must not carry an assessment: %+v", assessment)
	}
}

func TestFailureModeOpenIsExplicitlyDegraded(t *testing.T) {
	server := rawServer(t, 500, "")
	classifier := newClassifier(t, server.URL, func(c *Config) { c.FailureMode = FailOpen })
	assessment, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Triggered || assessment.Score != 0 || assessment.Reason != reasonDegraded {
		t.Fatalf("unexpected assessment %+v", assessment)
	}
	if assessment.Metadata["classifier_degraded"] != true || assessment.Metadata["classifier_failure"] != "status" {
		t.Fatalf("failure must be visible in metadata: %+v", assessment.Metadata)
	}
}

func TestFailureModeOpenCoversEveryFailureKind(t *testing.T) {
	server := rawServer(t, 200, `{"scores":[7]}`)
	classifier := newClassifier(t, server.URL, func(c *Config) {
		c.FailureMode, c.MaxChunks, c.ChunkRunes = FailOpen, 1, 64
	})
	assessment, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
	if err != nil || assessment.Metadata["classifier_failure"] != "invalid_score" {
		t.Fatalf("invalid score: %+v, %v", assessment, err)
	}
	assessment, err = classifier.DetectPromptInjection(context.Background(), []string{strings.Repeat("x", 1000)})
	if err != nil || assessment.Metadata["classifier_failure"] != "too_many_chunks" {
		t.Fatalf("too many chunks: %+v, %v", assessment, err)
	}

	unreachable := newServer(t, func(http.ResponseWriter, *http.Request) {})
	url := unreachable.URL
	unreachable.Close()
	classifier = newClassifier(t, url, func(c *Config) { c.FailureMode = FailOpen })
	assessment, err = classifier.DetectPromptInjection(context.Background(), []string{"x"})
	if err != nil || assessment.Metadata["classifier_failure"] != "transport" {
		t.Fatalf("transport: %+v, %v", assessment, err)
	}
}

func TestTransportFailureIsClassified(t *testing.T) {
	server := newServer(t, func(http.ResponseWriter, *http.Request) {})
	url := server.URL
	server.Close()
	classifier := newClassifier(t, url, nil)
	_, err := classifier.DetectPromptInjection(context.Background(), []string{canary})
	assertKind(t, err, FailureTransport)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("transport failure must not look like a context error")
	}
}

func TestErrorsNeverLeakTextOrEndpoint(t *testing.T) {
	servers := map[string]*httptest.Server{
		"status":    rawServer(t, 500, canary),
		"json":      rawServer(t, 200, canary),
		"score":     rawServer(t, 200, `{"scores":[9]}`),
		"transport": newServer(t, func(http.ResponseWriter, *http.Request) {}),
	}
	transportURL := servers["transport"].URL
	servers["transport"].Close()

	for name, server := range servers {
		t.Run(name, func(t *testing.T) {
			url := server.URL
			if name == "transport" {
				url = transportURL
			}
			classifier := newClassifier(t, url+"/path?token=endpoint-secret", nil)
			_, err := classifier.DetectPromptInjection(context.Background(), []string{canary})
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, forbidden := range []string{canary, "endpoint-secret", "127.0.0.1"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("error %q leaks %q", err, forbidden)
				}
			}
		})
	}
}

func TestCallerCancellationIsAlwaysAnError(t *testing.T) {
	for _, mode := range []FailureMode{FailClosed, FailOpen} {
		t.Run(string(mode), func(t *testing.T) {
			started := make(chan struct{}, 1)
			server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				blockUntilClientGone(r, started)
			})
			classifier := newClassifier(t, server.URL, func(c *Config) { c.FailureMode = mode })

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				<-started
				cancel()
			}()
			_, err := classifier.DetectPromptInjection(ctx, []string{"x"})
			assertKind(t, err, FailureCanceled)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error does not unwrap to context.Canceled: %v", err)
			}
		})
	}
}

func TestCancelledContextSendsNothing(t *testing.T) {
	var calls atomic.Int32
	server := newServer(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	classifier := newClassifier(t, server.URL, func(c *Config) { c.FailureMode = FailOpen })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := classifier.DetectPromptInjection(ctx, []string{"x"})
	assertKind(t, err, FailureCanceled)
	if calls.Load() != 0 {
		t.Fatal("a cancelled context must not reach the sidecar")
	}
}

func TestCallerDeadlineIsReportedAsCancellation(t *testing.T) {
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) { blockUntilClientGone(r, nil) })
	classifier := newClassifier(t, server.URL, func(c *Config) { c.FailureMode = FailOpen })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err := classifier.DetectPromptInjection(ctx, []string{"x"})
	assertKind(t, err, FailureCanceled)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error does not unwrap to context.DeadlineExceeded: %v", err)
	}
}

func TestClientTimeoutIsSubjectToFailureMode(t *testing.T) {
	for _, mode := range []FailureMode{FailClosed, FailOpen} {
		t.Run(string(mode), func(t *testing.T) {
			started := make(chan struct{}, 1)
			server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
				blockUntilClientGone(r, started) // the sidecar never answers
			})
			classifier := newClassifier(t, server.URL, func(c *Config) {
				c.Timeout, c.FailureMode = 50*time.Millisecond, mode
			})

			assessment, err := classifier.DetectPromptInjection(context.Background(), []string{"x"})
			select {
			case <-started:
			default:
				t.Fatal("the sidecar was never reached")
			}
			if mode == FailClosed {
				assertKind(t, err, FailureTimeout)
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("error does not unwrap to context.DeadlineExceeded: %v", err)
				}
				return
			}
			if err != nil || assessment.Metadata["classifier_failure"] != "timeout" || assessment.Triggered {
				t.Fatalf("got %+v, %v", assessment, err)
			}
		})
	}
}

func TestTimeoutBoundsTheWholeDetection(t *testing.T) {
	var calls atomic.Int32
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, `{"scores":[0.1]}`)
			return
		}
		blockUntilClientGone(r, nil)
	})
	classifier := newClassifier(t, server.URL, func(c *Config) {
		c.Timeout, c.BatchSize = 100*time.Millisecond, 1
	})
	_, err := classifier.DetectPromptInjection(context.Background(), []string{"a", "b", "c"})
	assertKind(t, err, FailureTimeout)
	if calls.Load() != 2 {
		t.Fatalf("expected the second batch to time out and stop, calls=%d", calls.Load())
	}
}

func TestNoImplicitRetry(t *testing.T) {
	var calls atomic.Int32
	server := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	classifier := newClassifier(t, server.URL, nil)
	_, _ = classifier.DetectPromptInjection(context.Background(), []string{"x"})
	if calls.Load() != 1 {
		t.Fatalf("expected a single attempt, got %d", calls.Load())
	}
}

func TestConcurrentDetections(t *testing.T) {
	server := scoresServer(t, func(text string) float64 {
		if text == "attack" {
			return 0.9
		}
		return 0.1
	})
	classifier := newClassifier(t, server.URL, nil)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(attack bool) {
			defer wg.Done()
			text := "hello"
			if attack {
				text = "attack"
			}
			assessment, err := classifier.DetectPromptInjection(context.Background(), []string{text})
			if err != nil || assessment.Triggered != attack {
				t.Errorf("attack=%v: %+v, %v", attack, assessment, err)
			}
		}(i%2 == 0)
	}
	wg.Wait()
}
