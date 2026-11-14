package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Published System One price (docs.typesafe.ai models page and help.typesafe.ai
// pricing article, read 14/11/2026): USD 0.042 per million input tokens, output
// tokens free, no per-request fee.
const JevUSDPerMillionInputTokens = 0.042

// JevUpstream is the documented System One endpoint.
const JevUpstream = "https://api.typesafe.ai/v1/systemone"

// Budget bounds paid traffic. The worst case is checked before every call.
type Budget struct {
	MaxCalls int     `json:"max_calls"`
	MaxUSD   float64 `json:"max_usd"`
	// StopAfter consecutive 402/429 answers stops paid traffic.
	StopAfter int `json:"stop_after"`
}

// DefaultBudget is the L12b cap: far below the USD 5 L12 ceiling.
var DefaultBudget = Budget{MaxCalls: 200, MaxUSD: 1, StopAfter: 2}

// CostUSD converts input tokens to dollars at the published price.
func CostUSD(inputTokens int64) float64 {
	return float64(inputTokens) * JevUSDPerMillionInputTokens / 1e6
}

// MaxTokensPerRequest is the documented System One per-request input limit.
const MaxTokensPerRequest = 64_000

// WorstCaseUSD bounds one call before it is sent. Billed input tokens include
// a server-side overhead (a 375-byte probe was billed 339 tokens), so the body
// size is no bound: the documented per-request maximum is used instead.
func WorstCaseUSD() float64 { return CostUSD(MaxTokensPerRequest) }

// JevEntry is one cached System One answer, reduced to the fields the judge
// decodes. It never holds the request text or headers.
type JevEntry struct {
	Model      string                     `json:"model"`
	Answers    map[string]json.RawMessage `json:"answers"`
	Usage      map[string]int64           `json:"usage"`
	UpstreamMS float64                    `json:"upstream_ms"`
}

// JevKey keys a judge request: the exact masked body, which already contains
// the model version, the question and its fixed instructions.
func JevKey(body []byte) string { return BytesSHA256(append([]byte("jev\n"), body...)) }

// LedgerLine is one paid call. It never contains text, keys or response bodies.
type LedgerLine struct {
	Time        string  `json:"time"`
	Key         string  `json:"key"`
	Status      int     `json:"status"`
	InputTokens int64   `json:"input_tokens"`
	CostUSD     float64 `json:"cost_usd"`
	SpentUSD    float64 `json:"spent_usd"`
	MS          float64 `json:"ms"`
	BodyBytes   int     `json:"body_bytes"`
}

// Egress leak guard: independent of the service's masking patterns, it
// refuses to forward a body whose text still looks like a secret or personal
// identifier. It is a second line of defense, not a PII detector.
var leakPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"email", regexp.MustCompile(`[^\s@\[\]<>()"']+@[^\s@\[\]<>()"']+\.[A-Za-z\p{L}]{2,}`)},
	{"iban", regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,3})?\b`)},
	{"card", regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)},
	{"phone_fr", regexp.MustCompile(`(?:\+33[ .]?|\b0)[1-9](?:[ .-]?\d{2}){4}\b`)},
	{"ipv4", regexp.MustCompile(`\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b`)},
	{"aws_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"provider_key", regexp.MustCompile(`\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`)},
	{"slack_token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"password_assignment", regexp.MustCompile(`(?i)\b(?:password|passwd|mot de passe|mdp|secret|token)\s*[:=]\s*[^\s\[]{6,}`)},
}

// LeakKinds lists the sensitive shapes still present in text (sorted, distinct).
func LeakKinds(text string) []string {
	var kinds []string
	for _, pattern := range leakPatterns {
		if pattern.re.MatchString(text) {
			kinds = append(kinds, pattern.kind)
		}
	}
	sort.Strings(kinds)
	return kinds
}

// JevProxy sits between the service's System One client and the real API. The
// service only ever holds a dummy key and talks to this loopback proxy; the
// real key lives here, in memory. In cache mode no upstream call is possible.
type JevProxy struct {
	live     bool
	upstream string
	key      []byte
	cache    *Cache
	budget   Budget
	ledger   io.Writer
	client   *http.Client
	trace    *tracer
	delay    bool
	now      func() time.Time

	mu          sync.Mutex
	stats       JudgeStats
	consecutive int
	leaks       map[string]int
}

// JevProxyConfig configures a proxy. Key is required in live mode and must be
// absent in cache mode.
type JevProxyConfig struct {
	Live     bool
	Upstream string
	Key      []byte
	Cache    *Cache
	Budget   Budget
	Ledger   io.Writer
	Delay    bool
	Client   *http.Client
}

func newJevProxy(cfg JevProxyConfig, trace *tracer) (*JevProxy, error) {
	if cfg.Live && len(cfg.Key) == 0 {
		return nil, errors.New("live judge mode needs a key")
	}
	if !cfg.Live && len(cfg.Key) != 0 {
		return nil, errors.New("cache-only judge mode must not hold a key")
	}
	if cfg.Live && (cfg.Budget.MaxCalls <= 0 || cfg.Budget.MaxUSD <= 0 || cfg.Budget.StopAfter <= 0) {
		return nil, errors.New("live judge mode needs a positive budget")
	}
	if cfg.Upstream == "" {
		cfg.Upstream = JevUpstream
	}
	client := cfg.Client
	if client == nil {
		client = &http.Client{
			Transport:     &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second},
			CheckRedirect: noRedirect,
			Timeout:       30 * time.Second,
		}
	}
	ledger := cfg.Ledger
	if ledger == nil {
		ledger = io.Discard
	}
	return &JevProxy{
		live: cfg.Live, upstream: cfg.Upstream, key: cfg.Key, cache: cfg.Cache, budget: cfg.Budget,
		ledger: ledger, client: client, trace: trace, delay: cfg.Delay, now: time.Now, leaks: map[string]int{},
	}, nil
}

// Stats returns the counters and how many requests each leak kind blocked.
func (p *JevProxy) Stats() (JudgeStats, map[string]int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	leaks := make(map[string]int, len(p.leaks))
	for kind, n := range p.leaks {
		leaks[kind] = n
	}
	return p.stats, leaks
}

type jevRequest struct {
	Model string `json:"model"`
	State struct {
		UntrustedText string `json:"untrusted_text"`
	} `json:"state"`
	Questions map[string]json.RawMessage `json:"questions"`
}

func writeJevError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (p *JevProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/systemone" {
		writeJevError(w, http.StatusNotFound, "not found")
		return
	}
	p.mu.Lock()
	p.stats.Requests++
	p.mu.Unlock()
	body, err := io.ReadAll(io.LimitReader(r.Body, maxProxyBody+1))
	var request jevRequest
	if err == nil && len(body) <= maxProxyBody {
		err = json.Unmarshal(body, &request)
	}
	if err != nil || len(body) > maxProxyBody || request.Model == "" || len(request.Questions) == 0 {
		p.fail(func(s *JudgeStats) { s.Failures++ })
		writeJevError(w, http.StatusBadRequest, "malformed judge request")
		return
	}
	if kinds := LeakKinds(request.State.UntrustedText); len(kinds) > 0 {
		p.mu.Lock()
		p.stats.EgressBlocked++
		for _, kind := range kinds {
			p.leaks[kind]++
		}
		p.mu.Unlock()
		p.trace.with(func(t *caseTrace) { t.judgeCalls++; t.judgeCache = "egress_blocked" })
		writeJevError(w, http.StatusBadRequest, "egress guard refused the masked text")
		return
	}
	key := JevKey(body)
	var entry JevEntry
	ok, err := p.cache.Get(key, &entry)
	if err != nil {
		p.fail(func(s *JudgeStats) { s.Failures++ })
		writeJevError(w, http.StatusInternalServerError, "cache failure")
		return
	}
	source := "hit"
	if ok {
		p.mu.Lock()
		p.stats.CacheHits++
		p.mu.Unlock()
		if p.delay {
			sleepContext(r.Context(), time.Duration(entry.UpstreamMS*float64(time.Millisecond)))
		}
	} else {
		if !p.live {
			p.fail(func(s *JudgeStats) { s.Refused++ })
			p.trace.with(func(t *caseTrace) { t.judgeCalls++; t.judgeCache = "miss" })
			writeJevError(w, http.StatusServiceUnavailable, "no cached judge answer (cache-only mode)")
			return
		}
		var status int
		entry, status, err = p.call(r.Context(), key, request.Model, body)
		if err != nil {
			p.trace.with(func(t *caseTrace) { t.judgeCalls++; t.judgeCache = "error" })
			writeJevError(w, status, err.Error())
			return
		}
		source = "live"
	}
	probability := noulProbability(entry)
	tokens := entry.Usage["input_tokens"]
	p.trace.with(func(t *caseTrace) {
		t.judgeCalls++
		t.judgeProb = probability
		t.judgeMS += entry.UpstreamMS
		t.tokens += tokens
		t.judgeCache = source
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Model   string                     `json:"model"`
		Answers map[string]json.RawMessage `json:"answers"`
		Usage   map[string]int64           `json:"usage"`
	}{entry.Model, entry.Answers, entry.Usage})
}

func (p *JevProxy) fail(fn func(*JudgeStats)) {
	p.mu.Lock()
	fn(&p.stats)
	p.mu.Unlock()
}

// call sends one paid request after checking the budget. Upstream bodies are
// never echoed: errors carry the status code only.
func (p *JevProxy) call(ctx context.Context, key, model string, body []byte) (JevEntry, int, error) {
	p.mu.Lock()
	switch {
	case p.stats.StopReason != "":
		p.mu.Unlock()
		p.fail(func(s *JudgeStats) { s.Refused++ })
		return JevEntry{}, http.StatusServiceUnavailable, errors.New("paid traffic stopped: " + p.stats.StopReason)
	case p.stats.Upstream >= p.budget.MaxCalls:
		p.stats.StopReason = fmt.Sprintf("call cap %d reached", p.budget.MaxCalls)
		p.stats.Refused++
		p.mu.Unlock()
		return JevEntry{}, http.StatusServiceUnavailable, errors.New("paid traffic stopped: call cap")
	case p.stats.CostUSD+WorstCaseUSD() > p.budget.MaxUSD:
		p.stats.StopReason = fmt.Sprintf("worst-case cost would exceed USD %.2f", p.budget.MaxUSD)
		p.stats.Refused++
		p.mu.Unlock()
		return JevEntry{}, http.StatusServiceUnavailable, errors.New("paid traffic stopped: budget")
	}
	p.stats.Upstream++
	p.stats.BodyBytes += int64(len(body))
	p.mu.Unlock()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.upstream, bytes.NewReader(body))
	if err != nil {
		p.fail(func(s *JudgeStats) { s.Failures++ })
		return JevEntry{}, http.StatusBadGateway, errors.New("cannot build upstream request")
	}
	request.Header.Set("Authorization", "Bearer "+string(p.key))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "guardrail-bench")
	started := p.now()
	response, err := p.client.Do(request)
	if err != nil {
		p.fail(func(s *JudgeStats) { s.Failures++ })
		return JevEntry{}, http.StatusBadGateway, errors.New("upstream transport failure")
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxProxyBody+1))
	elapsed := float64(p.now().Sub(started).Microseconds()) / 1000
	line := LedgerLine{Time: p.now().UTC().Format(time.RFC3339), Key: key[:16], Status: response.StatusCode, MS: elapsed, BodyBytes: len(body)}
	defer func() {
		p.mu.Lock()
		line.SpentUSD = p.stats.CostUSD
		p.mu.Unlock()
		encoded, _ := json.Marshal(line)
		_, _ = p.ledger.Write(append(encoded, '\n'))
	}()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		p.stop("upstream 401: key refused")
		return JevEntry{}, http.StatusUnauthorized, errors.New("upstream status 401")
	case http.StatusPaymentRequired, http.StatusTooManyRequests:
		p.mu.Lock()
		p.consecutive++
		if p.consecutive >= p.budget.StopAfter {
			p.stats.StopReason = fmt.Sprintf("%d consecutive 402/429", p.consecutive)
		}
		p.stats.Failures++
		p.mu.Unlock()
		return JevEntry{}, response.StatusCode, fmt.Errorf("upstream status %d", response.StatusCode)
	default:
		p.fail(func(s *JudgeStats) { s.Failures++ })
		return JevEntry{}, response.StatusCode, fmt.Errorf("upstream status %d", response.StatusCode)
	}
	var decoded struct {
		Model   string                     `json:"model"`
		Answers map[string]json.RawMessage `json:"answers"`
		Usage   map[string]int64           `json:"usage"`
	}
	if readErr != nil || len(data) > maxProxyBody || json.Unmarshal(data, &decoded) != nil || decoded.Usage == nil {
		p.fail(func(s *JudgeStats) { s.Failures++ })
		return JevEntry{}, http.StatusBadGateway, errors.New("upstream answer is not the documented object")
	}
	tokens := decoded.Usage["input_tokens"]
	cost := CostUSD(tokens)
	line.InputTokens, line.CostUSD = tokens, cost
	p.mu.Lock()
	p.consecutive = 0
	p.stats.InputTokens += tokens
	p.stats.CostUSD += cost
	p.mu.Unlock()
	if decoded.Model != model {
		// A different version would be measured under the pinned name: stop, keep nothing.
		p.stop("upstream served another model version")
		return JevEntry{}, http.StatusBadGateway, errors.New("upstream served another model version")
	}
	entry := JevEntry{Model: decoded.Model, Answers: decoded.Answers, Usage: decoded.Usage, UpstreamMS: elapsed}
	if err := p.cache.Put(key, entry); err != nil {
		return JevEntry{}, http.StatusInternalServerError, errors.New("cache failure")
	}
	return entry, http.StatusOK, nil
}

func (p *JevProxy) stop(reason string) {
	p.mu.Lock()
	p.stats.StopReason = reason
	p.stats.Failures++
	p.mu.Unlock()
}

// noulProbability extracts the noul answer for reporting only; the service
// decodes and validates the answer itself.
func noulProbability(entry JevEntry) *float64 {
	for _, raw := range entry.Answers {
		var answer struct {
			Noul *float64 `json:"noul"`
		}
		if json.Unmarshal(raw, &answer) == nil && answer.Noul != nil {
			value := *answer.Noul
			return &value
		}
	}
	return nil
}

// OpenLedger appends to the private paid-call ledger.
func OpenLedger(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}
