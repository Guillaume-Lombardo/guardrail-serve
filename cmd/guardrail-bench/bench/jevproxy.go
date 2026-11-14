package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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

// Budget bounds paid traffic. Its caps are cumulative over the ledger (every
// earlier run and process included), and the worst case of the next call is
// checked before it is sent.
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
	Billing     string  `json:"billing"`
	// Attempt pairs the reservation written before a call with its settlement.
	Attempt string `json:"attempt,omitempty"`
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
	ledger   *Ledger
	client   *http.Client
	trace    *tracer
	delay    bool
	now      func() time.Time
	prior    LedgerTotals

	mu          sync.Mutex
	stats       JudgeStats
	consecutive int
	inflightUSD float64
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
	Ledger   *Ledger // required in live mode: the durable spend the caps count from
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
	ledger := &Ledger{w: io.Discard}
	switch {
	case cfg.Ledger != nil:
		ledger = cfg.Ledger
	case cfg.Live:
		return nil, errors.New("live judge mode needs the durable ledger")
	}
	prior := ledger.Prior()
	return &JevProxy{
		live: cfg.Live, upstream: cfg.Upstream, key: cfg.Key, cache: cfg.Cache, budget: cfg.Budget,
		ledger: ledger, client: client, trace: trace, delay: cfg.Delay, now: time.Now, prior: prior, leaks: map[string]int{},
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
		// An entry written by an earlier format may hold more than the reduced
		// answer: it is reduced again, and refused when it does not fit.
		entry, err = reduceAnswer(entry.response(), request, entry.UpstreamMS)
		if err != nil {
			p.fail(func(s *JudgeStats) { s.Failures++ })
			p.trace.with(func(t *caseTrace) { t.judgeCalls++; t.judgeCache = "error" })
			writeJevError(w, http.StatusBadGateway, "cached judge answer is not a reduced answer")
			return
		}
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
		entry, status, err = p.call(r.Context(), key, request, body)
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
		if source == "hit" {
			// A live call already traced its billed tokens when it settled.
			t.tokens += tokens
		}
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
// never echoed: errors carry the status code only. The worst case of the call
// is reserved before sending; when the billing of an attempt cannot be known
// (transport failure, 5xx, unreadable 200 or invalid usage) the reservation is
// kept as spent, so an unknown outcome can never let the budget drift.
func (p *JevProxy) call(ctx context.Context, key string, asked jevRequest, body []byte) (JevEntry, int, error) {
	worst := WorstCaseUSD()
	p.mu.Lock()
	switch {
	case p.stats.StopReason != "":
		p.stats.Refused++
		reason := p.stats.StopReason
		p.mu.Unlock()
		return JevEntry{}, http.StatusServiceUnavailable, errors.New("paid traffic stopped: " + reason)
	case p.prior.Calls+p.stats.Upstream >= p.budget.MaxCalls:
		p.stats.StopReason = fmt.Sprintf("cumulative call cap %d reached", p.budget.MaxCalls)
		p.stats.Refused++
		p.mu.Unlock()
		return JevEntry{}, http.StatusServiceUnavailable, errors.New("paid traffic stopped: call cap")
	case p.prior.SpentUSD+p.stats.CostUSD+p.stats.UnknownBillingUSD+p.inflightUSD+worst > p.budget.MaxUSD:
		p.stats.StopReason = fmt.Sprintf("worst-case cumulative cost would exceed USD %.2f", p.budget.MaxUSD)
		p.stats.Refused++
		p.mu.Unlock()
		return JevEntry{}, http.StatusServiceUnavailable, errors.New("paid traffic stopped: budget")
	}
	// The reservation reaches the disk before the request leaves, and while the
	// admission lock is held: a crash after the call still finds the worst case
	// spent on the next start, and once a write fails no other request can be
	// admitted. No durable reservation, no call.
	attempt, err := newAttemptID()
	reserved := LedgerLine{Time: p.now().UTC().Format(time.RFC3339), Key: key[:16], BodyBytes: len(body), Billing: BillingReserved, CostUSD: worst, Attempt: attempt}
	if err == nil {
		err = p.ledger.record(reserved)
	}
	if err != nil {
		p.stats.StopReason = "the ledger cannot be written"
		p.stats.Failures++
		p.mu.Unlock()
		return JevEntry{}, http.StatusServiceUnavailable, errors.New("paid traffic stopped: ledger write failed")
	}
	p.stats.Upstream++
	p.stats.BodyBytes += int64(len(body))
	p.inflightUSD += worst
	p.mu.Unlock()

	// Every attempt then settles its reservation in a second text-free line and
	// charges its case, whether the answer is then used or not.
	line := LedgerLine{Time: reserved.Time, Key: reserved.Key, BodyBytes: len(body), Billing: BillingUnknown, Attempt: attempt}
	defer func() {
		p.mu.Lock()
		p.inflightUSD -= worst
		switch line.Billing {
		case BillingKnown:
			p.stats.InputTokens += line.InputTokens
			p.stats.CostUSD += line.CostUSD
		case BillingUnknown:
			p.stats.UnknownBillingUSD += worst
			line.CostUSD = worst
		}
		line.SpentUSD = p.prior.SpentUSD + p.stats.CostUSD + p.stats.UnknownBillingUSD
		p.mu.Unlock()
		p.trace.with(func(t *caseTrace) {
			switch line.Billing {
			case BillingKnown:
				t.tokens += line.InputTokens
			case BillingUnknown:
				t.unknownUSD += worst
			}
		})
		if err := p.ledger.record(line); err != nil {
			// The reservation stays on disk as the worst case: stop, never undercount.
			p.mu.Lock()
			p.stats.StopReason = "the ledger cannot be written"
			p.mu.Unlock()
		}
	}()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.upstream, bytes.NewReader(body))
	if err != nil {
		line.Billing = BillingNone
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
		line.MS = float64(p.now().Sub(started).Microseconds()) / 1000
		p.fail(func(s *JudgeStats) { s.Failures++ })
		return JevEntry{}, http.StatusBadGateway, errors.New("upstream transport failure")
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxProxyBody+1))
	elapsed := float64(p.now().Sub(started).Microseconds()) / 1000
	line.Status, line.MS = response.StatusCode, elapsed

	switch {
	case response.StatusCode == http.StatusOK:
	case response.StatusCode == http.StatusUnauthorized:
		line.Billing = BillingNone
		p.stop("upstream 401: key refused")
		return JevEntry{}, http.StatusUnauthorized, errors.New("upstream status 401")
	case response.StatusCode == http.StatusPaymentRequired || response.StatusCode == http.StatusTooManyRequests:
		line.Billing = BillingNone
		p.mu.Lock()
		p.consecutive++
		if p.consecutive >= p.budget.StopAfter {
			p.stats.StopReason = fmt.Sprintf("%d consecutive 402/429", p.consecutive)
		}
		p.stats.Failures++
		p.mu.Unlock()
		return JevEntry{}, response.StatusCode, fmt.Errorf("upstream status %d", response.StatusCode)
	case response.StatusCode >= 400 && response.StatusCode < 500:
		// A documented client error refuses the request before inference.
		line.Billing = BillingNone
		p.fail(func(s *JudgeStats) { s.Failures++ })
		return JevEntry{}, response.StatusCode, fmt.Errorf("upstream status %d", response.StatusCode)
	default:
		p.fail(func(s *JudgeStats) { s.Failures++ })
		return JevEntry{}, http.StatusBadGateway, fmt.Errorf("upstream status %d", response.StatusCode)
	}
	if readErr != nil || len(data) > maxProxyBody {
		p.fail(func(s *JudgeStats) { s.Failures++ })
		return JevEntry{}, http.StatusBadGateway, errors.New("upstream answer is not the documented object")
	}
	var decoded jevResponse
	if json.Unmarshal(data, &decoded) != nil || decoded.Usage.InputTokens == nil || *decoded.Usage.InputTokens < 0 {
		p.fail(func(s *JudgeStats) { s.Failures++ })
		return JevEntry{}, http.StatusBadGateway, errors.New("upstream answer is not the documented object")
	}
	line.Billing = BillingKnown
	line.InputTokens = *decoded.Usage.InputTokens
	line.CostUSD = CostUSD(line.InputTokens)
	p.mu.Lock()
	p.consecutive = 0
	p.mu.Unlock()
	if decoded.Model != asked.Model {
		// A different version would be measured under the pinned name: stop, keep nothing.
		p.stop("upstream served another model version")
		return JevEntry{}, http.StatusBadGateway, errors.New("upstream served another model version")
	}
	entry, err := reduceAnswer(decoded, asked, elapsed)
	if err != nil {
		p.fail(func(s *JudgeStats) { s.Failures++ })
		return JevEntry{}, http.StatusBadGateway, err
	}
	if err := p.cache.Put(key, entry); err != nil {
		return JevEntry{}, http.StatusInternalServerError, errors.New("cache failure")
	}
	return entry, http.StatusOK, nil
}

// Billing states of a ledger line.
const (
	BillingKnown   = "known"   // usage reported: the input tokens are billed
	BillingNone    = "none"    // refused before inference (4xx): nothing billed
	BillingUnknown = "unknown" // outcome unknown: the worst case is counted as spent
	// BillingReserved is the worst case written before a call, until settled.
	BillingReserved = "reserved"
)

type jevResponse struct {
	Model   string                     `json:"model"`
	Answers map[string]json.RawMessage `json:"answers"`
	Usage   struct {
		InputTokens  *int64 `json:"input_tokens"`
		OutputTokens *int64 `json:"output_tokens"`
	} `json:"usage"`
}

// response is a cached entry seen as an upstream answer, to be reduced again.
func (e JevEntry) response() jevResponse {
	var decoded jevResponse
	decoded.Model, decoded.Answers = e.Model, e.Answers
	if tokens, ok := e.Usage["input_tokens"]; ok {
		decoded.Usage.InputTokens = &tokens
	}
	if tokens, ok := e.Usage["output_tokens"]; ok {
		decoded.Usage.OutputTokens = &tokens
	}
	return decoded
}

// reduceAnswer keeps only what the service decodes: the answer of the model
// that was asked, to the one asked question, as a noul probability in [0, 1],
// with its usage. Any other upstream field (an explanation, an echo of the
// input) is dropped before the answer is cached or forwarded.
func reduceAnswer(decoded jevResponse, request jevRequest, elapsed float64) (JevEntry, error) {
	if len(request.Questions) != 1 {
		return JevEntry{}, errors.New("judge request must ask exactly one question")
	}
	if decoded.Model != request.Model || decoded.Usage.InputTokens == nil || *decoded.Usage.InputTokens < 0 {
		return JevEntry{}, errors.New("judge answer is not for the asked model or has no usage")
	}
	var name string
	for question := range request.Questions {
		name = question
	}
	raw, ok := decoded.Answers[name]
	if !ok || len(decoded.Answers) != 1 {
		return JevEntry{}, errors.New("upstream answer does not match the asked question")
	}
	var answer struct {
		Type string   `json:"type"`
		Noul *float64 `json:"noul"`
	}
	if json.Unmarshal(raw, &answer) != nil || answer.Type != "noul" || answer.Noul == nil || *answer.Noul < 0 || *answer.Noul > 1 {
		return JevEntry{}, errors.New("upstream answer is not a noul probability")
	}
	reduced, err := json.Marshal(struct {
		Type string  `json:"type"`
		Noul float64 `json:"noul"`
	}{"noul", *answer.Noul})
	if err != nil {
		return JevEntry{}, err
	}
	usage := map[string]int64{"input_tokens": *decoded.Usage.InputTokens}
	if decoded.Usage.OutputTokens != nil && *decoded.Usage.OutputTokens >= 0 {
		usage["output_tokens"] = *decoded.Usage.OutputTokens
	}
	return JevEntry{Model: decoded.Model, Answers: map[string]json.RawMessage{name: reduced}, Usage: usage, UpstreamMS: elapsed}, nil
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
