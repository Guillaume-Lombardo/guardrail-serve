package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// maxProxyBody bounds every request and response body crossing a proxy.
const maxProxyBody = 4 << 20

// ScoreEntry is one cached /classify answer. It holds scores and timing, never text.
type ScoreEntry struct {
	Scores     []float64 `json:"scores"`
	UpstreamMS float64   `json:"upstream_ms"`
}

// Cache stores JSON entries outside Git, one file per key, keyed by a sha256.
type Cache struct{ dir string }

// NewCache creates (if needed) a private cache directory.
func NewCache(dir string) (*Cache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Cache{dir: dir}, nil
}

func (c *Cache) path(key string) string { return filepath.Join(c.dir, key[:2], key+".json") }

// Get decodes a cached entry; ok is false when absent.
func (c *Cache) Get(key string, v any) (bool, error) {
	data, err := os.ReadFile(c.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return false, fmt.Errorf("cache entry %s is corrupt: %w", key[:12], err)
	}
	return true, nil
}

// Put stores an entry atomically.
func (c *Cache) Put(key string, v any) error {
	path := c.path(key)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return WriteJSON(path, v)
}

// SidecarKey keys a classifier request: the ready label (model@revision) and the exact body.
func SidecarKey(readyLabel string, body []byte) string {
	return BytesSHA256(append([]byte("sidecar\n"+readyLabel+"\n"), body...))
}

// caseTrace collects what the proxies saw while one case was evaluated.
type caseTrace struct {
	scores     []float64
	modelMS    float64
	modelCalls int
	judgeCalls int
	judgeProb  *float64
	judgeMS    float64
	tokens     int64
	unknownUSD float64
	judgeCache string
}

// tracer is shared by the proxies: the runner evaluates one case at a time.
type tracer struct {
	mu      sync.Mutex
	current *caseTrace
}

func (t *tracer) begin() {
	t.mu.Lock()
	t.current = &caseTrace{}
	t.mu.Unlock()
}

func (t *tracer) end() caseTrace {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current == nil {
		return caseTrace{}
	}
	trace := *t.current
	t.current = nil
	return trace
}

func (t *tracer) with(fn func(*caseTrace)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.current != nil {
		fn(t.current)
	}
}

// SidecarProxy sits between the service and the classifier. In record mode it
// forwards every request and stores the scores and upstream latency; in replay
// mode it answers from the cache only (a miss is a 503, never an invented
// score), optionally sleeping the recorded upstream latency.
type SidecarProxy struct {
	upstream   string
	readyLabel string
	cache      *Cache
	replay     bool
	delay      bool
	client     *http.Client
	trace      *tracer

	mu    sync.Mutex
	stats SidecarStats
	drift int
}

func newSidecarProxy(upstream, readyLabel string, cache *Cache, replay, delay bool, trace *tracer) *SidecarProxy {
	return &SidecarProxy{
		upstream: upstream, readyLabel: readyLabel, cache: cache, replay: replay, delay: delay, trace: trace,
		client: &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: noRedirect},
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Stats returns a snapshot of the proxy counters and the number of recorded
// requests whose fresh scores differed from an earlier cached answer.
func (p *SidecarProxy) Stats() (SidecarStats, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats, p.drift
}

func (p *SidecarProxy) count(fn func(*SidecarStats)) {
	p.mu.Lock()
	fn(&p.stats)
	p.mu.Unlock()
}

func (p *SidecarProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/classify" {
		http.Error(w, `{"detail":"not found"}`, http.StatusNotFound)
		return
	}
	p.count(func(s *SidecarStats) { s.Requests++ })
	body, err := io.ReadAll(io.LimitReader(r.Body, maxProxyBody+1))
	if err != nil || len(body) > maxProxyBody {
		p.count(func(s *SidecarStats) { s.Failures++ })
		http.Error(w, `{"detail":"bad request"}`, http.StatusBadRequest)
		return
	}
	key := SidecarKey(p.readyLabel, body)
	var entry ScoreEntry
	if p.replay {
		ok, err := p.cache.Get(key, &entry)
		if err != nil || !ok {
			p.count(func(s *SidecarStats) { s.Misses++ })
			http.Error(w, `{"detail":"no cached score"}`, http.StatusServiceUnavailable)
			return
		}
		p.count(func(s *SidecarStats) { s.CacheHits++ })
		if p.delay {
			sleepContext(r.Context(), time.Duration(entry.UpstreamMS*float64(time.Millisecond)))
		}
	} else {
		entry, err = p.forward(r.Context(), body)
		if err != nil {
			p.count(func(s *SidecarStats) { s.Failures++ })
			http.Error(w, `{"detail":"upstream failure"}`, http.StatusBadGateway)
			return
		}
		p.count(func(s *SidecarStats) { s.Upstream++ })
		var previous ScoreEntry
		if ok, _ := p.cache.Get(key, &previous); ok && !sameScores(previous.Scores, entry.Scores) {
			p.mu.Lock()
			p.drift++
			p.mu.Unlock()
		}
		if err := p.cache.Put(key, entry); err != nil {
			p.count(func(s *SidecarStats) { s.Failures++ })
			http.Error(w, `{"detail":"cache failure"}`, http.StatusInternalServerError)
			return
		}
	}
	p.trace.with(func(t *caseTrace) {
		t.scores = append(t.scores, entry.Scores...)
		t.modelMS += entry.UpstreamMS
		t.modelCalls++
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Scores []float64 `json:"scores"`
	}{entry.Scores})
}

func (p *SidecarProxy) forward(ctx context.Context, body []byte) (ScoreEntry, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.upstream+"/classify", bytes.NewReader(body))
	if err != nil {
		return ScoreEntry{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	started := time.Now()
	response, err := p.client.Do(request)
	if err != nil {
		return ScoreEntry{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxProxyBody+1))
	elapsed := time.Since(started)
	if err != nil || len(data) > maxProxyBody {
		return ScoreEntry{}, errors.New("upstream body unreadable or too large")
	}
	if response.StatusCode != http.StatusOK {
		return ScoreEntry{}, fmt.Errorf("upstream status %d", response.StatusCode)
	}
	var decoded struct {
		Scores []float64 `json:"scores"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil || len(decoded.Scores) == 0 {
		return ScoreEntry{}, errors.New("upstream answer is not a scores object")
	}
	for _, score := range decoded.Scores {
		if math.IsNaN(score) || score < 0 || score > 1 {
			return ScoreEntry{}, errors.New("upstream score out of [0, 1]")
		}
	}
	return ScoreEntry{Scores: decoded.Scores, UpstreamMS: float64(elapsed.Microseconds()) / 1000}, nil
}

func sameScores(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sleepContext(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}
