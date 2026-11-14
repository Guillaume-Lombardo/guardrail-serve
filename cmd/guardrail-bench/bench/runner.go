package bench

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// JevFixed are the a priori judge settings of the protocol (never tuned).
var JevFixed = JevSettings{Model: "jev-1.14.0", Question: "noul", Threshold: 0.7, Timeout: "10s"}

// warmupTexts are fixed texts outside every corpus, sent before measuring.
var warmupTexts = []string{
	"Bonjour, peux-tu me résumer ce compte rendu de réunion en trois points ?",
	"Quelle est la différence entre une facture et un devis ?",
	"Merci de traduire cette phrase en anglais : le train part à huit heures.",
}

// RunConfig is one measured pass. Thresholds of test runs come from the frozen
// protocol, never from the command line.
type RunConfig struct {
	Root         string
	Corpus       string
	Mode         Mode
	Model        string
	SidecarURL   string // live classifier; empty means replay from the cache
	SidecarImage string
	ReplayDelay  bool
	Threshold    float64
	Zone         *Zone
	JevLive      bool
	JevKey       []byte
	JevUpstream  string
	JevClient    *http.Client
	Budget       Budget
	CacheDir     string
	Protocol     *Protocol
	ProtocolSHA  string
	Warmup       int
	RunID        string
	LogOutput    io.Writer
}

// Validate enforces the protocol constraints before anything runs.
func (c RunConfig) Validate() error {
	if _, err := ParseMode(string(c.Mode)); err != nil {
		return err
	}
	if c.Mode.usesSidecar() {
		if _, err := LookupModel(c.Model); err != nil {
			return err
		}
	} else if c.Model != "" {
		return fmt.Errorf("mode %s takes no model", c.Mode)
	}
	if c.Mode == ModeCascade && c.Model != CascadePrimary {
		return fmt.Errorf("the cascade primary is %s", CascadePrimary)
	}
	if c.Mode.usesJudge() && c.Corpus != CorpusTest {
		return fmt.Errorf("the judge runs on %s only, never on %s", CorpusTest, c.Corpus)
	}
	if c.Mode == ModeCascade && (c.JevLive || c.SidecarURL != "") {
		return errors.New("the cascade replays cached scores and judge answers only")
	}
	if c.Corpus != CorpusCalibration && c.Mode != ModeRules && c.Protocol == nil {
		return fmt.Errorf("corpus %s needs the frozen protocol", c.Corpus)
	}
	if c.Corpus == CorpusCalibration && c.Mode != ModeRules && c.Mode != ModeUnion {
		return errors.New("only rules and classifier runs use the calibration split")
	}
	if c.Mode.usesSidecar() && (c.Threshold <= 0 || c.Threshold > 1) {
		return errors.New("threshold must be in (0, 1]")
	}
	if c.Mode == ModeCascade && c.Zone == nil {
		return errors.New("the cascade needs the frozen gray zone")
	}
	if c.CacheDir == "" {
		return errors.New("a cache directory is required")
	}
	if c.Protocol != nil && c.Corpus != CorpusCalibration && c.Mode.usesSidecar() {
		if err := c.Protocol.AllowedThreshold(c.Model, c.Threshold); err != nil {
			return err
		}
	}
	if c.Mode.usesJudge() {
		if err := c.Protocol.CheckJev(JevFixed); err != nil {
			return err
		}
	}
	if c.Mode == ModeCascade && (c.Zone.Lower != c.Protocol.Zone.Lower || c.Zone.Upper != c.Protocol.Zone.Upper || c.Threshold != c.Protocol.Zone.Upper) {
		return errors.New("the cascade must use the frozen zone and its upper bound as threshold")
	}
	return nil
}

// BuildRevision and BuildModified are set at link time by run-bench.sh build
// (-ldflags -X) when the toolchain cannot stamp VCS information.
var BuildRevision, BuildModified string

// Run evaluates every case of the corpus once, sequentially.
func Run(ctx context.Context, cfg RunConfig) (*RunFile, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	corpus, err := LoadCorpus(cfg.Root, cfg.Corpus)
	if err != nil {
		return nil, err
	}
	return runCorpus(ctx, cfg, corpus)
}

// runCorpus evaluates the cases of an already loaded corpus.
func runCorpus(ctx context.Context, cfg RunConfig, corpus *LoadedCorpus) (*RunFile, error) {
	trace := &tracer{}
	env := map[string]string{"SEMANTIC_ENABLED": "false"}
	run := &RunFile{
		Format: RunFormat, Version: FormatVersion, RunID: cfg.RunID, Mode: cfg.Mode, Model: cfg.Model,
		Corpus: corpus.Name, CorpusSHA256: corpus.SHA256, ProtocolSHA256: cfg.ProtocolSHA, Concurrency: 1,
		Warmup: []float64{},
	}
	var sidecar *SidecarProxy
	var judge *JevProxy
	var closers []func()
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}()
	serve := func(handler http.Handler) (string, error) {
		listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
		if err != nil {
			return "", err
		}
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = server.Serve(listener) }()
		closers = append(closers, func() { _ = server.Close() })
		return "http://" + listener.Addr().String(), nil
	}

	if cfg.Mode.usesSidecar() {
		model, _ := LookupModel(cfg.Model)
		cache, err := NewCache(filepath.Join(cfg.CacheDir, "sidecar"))
		if err != nil {
			return nil, err
		}
		replay := cfg.SidecarURL == ""
		if !replay {
			ready, err := readyLabel(ctx, cfg.SidecarURL)
			if err != nil {
				return nil, err
			}
			if ready != model.ReadyLabel() {
				return nil, fmt.Errorf("sidecar serves %q, expected %q", ready, model.ReadyLabel())
			}
		}
		sidecar = newSidecarProxy(strings.TrimRight(cfg.SidecarURL, "/"), model.ReadyLabel(), cache, replay, cfg.ReplayDelay, trace)
		url, err := serve(sidecar)
		if err != nil {
			return nil, err
		}
		threshold := cfg.Threshold
		run.SemanticThreshold = &threshold
		run.SidecarReady, run.SidecarImage, run.SidecarReplay, run.ReplayDelay = model.ReadyLabel(), cfg.SidecarImage, replay, cfg.ReplayDelay && replay
		env["SEMANTIC_ENABLED"] = "true"
		env["SEMANTIC_URL"] = url + "/classify"
		env["SEMANTIC_FORMAT"] = "scores"
		env["SEMANTIC_THRESHOLD"] = strconv.FormatFloat(threshold, 'g', -1, 64)
		env["SEMANTIC_TIMEOUT"] = "120s"
		env["SEMANTIC_FAILURE_MODE"] = "closed"
	}
	if cfg.Mode.usesJudge() {
		cache, err := NewCache(filepath.Join(cfg.CacheDir, "jev"))
		if err != nil {
			return nil, err
		}
		var ledger io.Writer
		if cfg.JevLive {
			file, err := OpenLedger(filepath.Join(cfg.CacheDir, "jev-ledger.jsonl"))
			if err != nil {
				return nil, err
			}
			closers = append(closers, func() { _ = file.Close() })
			ledger = file
		}
		judge, err = newJevProxy(JevProxyConfig{
			Live: cfg.JevLive, Upstream: cfg.JevUpstream, Key: cfg.JevKey, Cache: cache, Budget: cfg.Budget,
			Ledger: ledger, Delay: cfg.ReplayDelay && !cfg.JevLive, Client: cfg.JevClient,
		}, trace)
		if err != nil {
			return nil, err
		}
		url, err := serve(judge)
		if err != nil {
			return nil, err
		}
		settings := JevFixed
		settings.ProxyMode = "cache"
		if cfg.JevLive {
			settings.ProxyMode = "live"
		}
		run.Jev = &settings
		env["SYSTEMONE_ENABLED"] = "true"
		env["SYSTEMONE_MODE"] = "judge_only"
		env["SYSTEMONE_BASE_URL"] = url
		env["SYSTEMONE_MODEL"] = settings.Model
		env["SYSTEMONE_API_KEY"] = DummyJudgeKey
		env["SYSTEMONE_QUESTION"] = settings.Question
		env["SYSTEMONE_THRESHOLD"] = strconv.FormatFloat(settings.Threshold, 'g', -1, 64)
		env["SYSTEMONE_TIMEOUT"] = settings.Timeout
		env["SYSTEMONE_FAILURE_MODE"] = "closed"
		if cfg.Mode == ModeCascade {
			zone := *cfg.Zone
			run.Zone = &zone
			env["SYSTEMONE_MODE"] = "cascade"
			env["SYSTEMONE_ZONE_LOWER"] = strconv.FormatFloat(zone.Lower, 'g', -1, 64)
			env["SYSTEMONE_ZONE_UPPER"] = strconv.FormatFloat(zone.Upper, 'g', -1, 64)
		}
	}
	policy := PolicyRules
	if cfg.Mode != ModeRules {
		policy = PolicyUnion
	}
	logOutput := cfg.LogOutput
	if logOutput == nil {
		logOutput = io.Discard
	}
	workDir, err := os.MkdirTemp("", "guardrail-bench-")
	if err != nil {
		return nil, err
	}
	closers = append(closers, func() { _ = os.RemoveAll(workDir) })
	service, err := StartService(ctx, workDir, policy, env, logOutput)
	if err != nil {
		return nil, err
	}
	closers = append(closers, func() { _ = service.Close() })

	run.Environment = hostEnvironment(cfg.Root)
	run.Environment.LoadBefore = loadAverage()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Minute}
	if sidecar != nil && !run.SidecarReplay {
		for i := 0; i < cfg.Warmup; i++ {
			text := warmupTexts[i%len(warmupTexts)]
			started := time.Now()
			if _, err := evaluate(ctx, client, service.URL, policy, "request", text); err != nil {
				return nil, fmt.Errorf("warmup failed: %w", err)
			}
			run.Warmup = append(run.Warmup, milliseconds(time.Since(started)))
		}
	}
	run.Started = time.Now().UTC().Format(time.RFC3339)
	for _, item := range corpus.Cases {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		trace.begin()
		started := time.Now()
		outcome, err := evaluate(ctx, client, service.URL, policy, item.InputType, item.Text)
		elapsed := milliseconds(time.Since(started))
		seen := trace.end()
		result := CaseResult{ID: item.ID, Lang: item.Lang, InputType: item.InputType, Label: item.Label, LatencyMS: elapsed,
			ModelMS: seen.modelMS, ModelCalls: seen.modelCalls, JudgeCalls: seen.judgeCalls, JudgeProb: seen.judgeProb,
			JudgeMS: seen.judgeMS, JudgeTokens: seen.tokens, JudgeCache: seen.judgeCache}
		if len(seen.scores) > 0 {
			best := seen.scores[0]
			for _, score := range seen.scores[1:] {
				best = max(best, score)
			}
			result.Score = &best
		}
		if err != nil {
			result.Status, result.ErrorKind = StatusError, errorKind(err)
		} else {
			result.Status = StatusOK
			result.Decision, result.Rules, result.Semantic, result.SemanticRule = outcome.decision, outcome.rules, outcome.semantic, outcome.semanticRule
		}
		run.Cases = append(run.Cases, result)
	}
	run.Finished = time.Now().UTC().Format(time.RFC3339)
	run.Environment.LoadAfter = loadAverage()
	if sidecar != nil {
		stats, drift := sidecar.Stats()
		if drift > 0 {
			return nil, fmt.Errorf("%d recorded score(s) differ from an earlier answer for the same text: inference is not deterministic", drift)
		}
		run.Sidecar = &stats
	}
	if judge != nil {
		stats, leaks := judge.Stats()
		run.Judge = &stats
		if len(leaks) > 0 {
			fmt.Fprintf(logOutput, "egress guard blocked: %v\n", leaks)
		}
	}
	if cfg.Mode.usesJudge() {
		run.Routes, err = systemOneRoutes(ctx, client, service.URL)
		if err != nil {
			return nil, err
		}
	}
	return run, nil
}

type outcome struct {
	decision     string
	rules        bool
	semantic     bool
	semanticRule string
}

// statusError is a non-2xx answer of the service: an error, never a detection.
type statusError struct{ status int }

func (e *statusError) Error() string { return fmt.Sprintf("service status %d", e.status) }

func errorKind(err error) string {
	var status *statusError
	if errors.As(err, &status) {
		return "http_" + strconv.Itoa(status.status)
	}
	return "transport"
}

func evaluate(ctx context.Context, client *http.Client, base, policy, inputType, text string) (outcome, error) {
	body, err := json.Marshal(map[string]any{"texts": []string{text}, "input_type": inputType})
	if err != nil {
		return outcome{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/guardrails/"+policy, bytes.NewReader(body))
	if err != nil {
		return outcome{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return outcome{}, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxProxyBody))
	if err != nil {
		return outcome{}, err
	}
	if response.StatusCode != http.StatusOK {
		return outcome{}, &statusError{status: response.StatusCode}
	}
	var decoded struct {
		PolicyDecision string `json:"policy_decision"`
		Findings       []struct {
			Detector string `json:"detector"`
			Rule     string `json:"rule"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil || decoded.PolicyDecision == "" {
		return outcome{}, errors.New("service answer is not a guardrail response")
	}
	result := outcome{decision: decoded.PolicyDecision}
	for _, finding := range decoded.Findings {
		switch finding.Detector {
		case Detector:
			result.rules = true
		case "semantic_prompt_injection":
			result.semantic = true
			result.semanticRule = finding.Rule
		}
	}
	return result, nil
}

func readyLabel(ctx context.Context, base string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/readyz", nil)
	if err != nil {
		return "", err
	}
	response, err := (&http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return "", fmt.Errorf("sidecar readyz: %w", err)
	}
	defer response.Body.Close()
	var decoded struct {
		Model string `json:"model"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<16)).Decode(&decoded) != nil {
		return "", fmt.Errorf("sidecar is not ready (status %d)", response.StatusCode)
	}
	return decoded.Model, nil
}

// systemOneRoutes reads the System One route and judgment counters from /metrics.
func systemOneRoutes(ctx context.Context, client *http.Client, base string) (map[string]int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/metrics", nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	routes := map[string]int{}
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		line := scanner.Text()
		for _, metric := range []string{"guardrail_systemone_routes_total{", "guardrail_systemone_judgments_total{"} {
			if !strings.HasPrefix(line, metric) {
				continue
			}
			labels, value, ok := strings.Cut(strings.TrimPrefix(line, metric), " ")
			if count, err := strconv.ParseFloat(value, 64); ok && err == nil {
				routes[strings.TrimSuffix(labels, "}")] = int(count)
			}
		}
	}
	return routes, scanner.Err()
}

func milliseconds(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func hostEnvironment(root string) Environment {
	env := Environment{GoVersion: runtime.Version(), GOMAXPROCS: runtime.GOMAXPROCS(0), NumCPU: runtime.NumCPU()}
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if name, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(name) == "model name" {
				env.CPUModel = strings.TrimSpace(value)
				break
			}
		}
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				env.BinaryRevision = setting.Value
			case "vcs.modified":
				env.BinaryModified = setting.Value == "true"
			}
		}
	}
	if env.BinaryRevision == "" {
		// Git worktrees whose repository lives outside the module get no VCS
		// stamp; run-bench.sh build injects the revision instead.
		env.BinaryRevision, env.BinaryModified = BuildRevision, BuildModified == "true"
	}
	if out, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output(); err == nil {
		env.Commit = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("git", "-C", root, "status", "--porcelain", "--untracked-files=no").Output(); err == nil {
		env.Dirty = len(bytes.TrimSpace(out)) > 0
	}
	return env
}

func loadAverage() string {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return ""
	}
	return strings.Join(fields[:3], " ")
}
