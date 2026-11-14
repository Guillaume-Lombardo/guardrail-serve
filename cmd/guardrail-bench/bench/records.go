package bench

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Mode is the service configuration of one run.
type Mode string

const (
	// ModeRules runs the deterministic prompt_injection detector only.
	ModeRules Mode = "rules"
	// ModeUnion runs the rules and the semantic classifier (both evaluated, no short-circuit).
	ModeUnion Mode = "union"
	// ModeJudge runs the rules and the System One judge on every text (judge_only).
	ModeJudge Mode = "judge"
	// ModeCascade runs the rules and the cascade classifier -> judge in the gray zone.
	ModeCascade Mode = "cascade"
)

// ParseMode validates a user-facing mode.
func ParseMode(value string) (Mode, error) {
	switch mode := Mode(value); mode {
	case ModeRules, ModeUnion, ModeJudge, ModeCascade:
		return mode, nil
	}
	return "", fmt.Errorf("unknown mode %q (expected rules, union, judge or cascade)", value)
}

// usesSidecar reports whether the run needs classifier scores.
func (m Mode) usesSidecar() bool { return m == ModeUnion || m == ModeCascade }

// usesJudge reports whether the run asks System One.
func (m Mode) usesJudge() bool { return m == ModeJudge || m == ModeCascade }

// Run formats.
const (
	RunFormat     = "guardrail-bench-run"
	BundleFormat  = "guardrail-bench-runs"
	FormatVersion = 1
)

// Zone is the closed gray zone of the cascade.
type Zone struct {
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
}

// JevSettings are the judge parameters of a run (no key, no URL secrets).
type JevSettings struct {
	Model     string  `json:"model"`
	Question  string  `json:"question"`
	Threshold float64 `json:"threshold"`
	Timeout   string  `json:"timeout"`
	ProxyMode string  `json:"proxy_mode"`
}

// Environment describes the host and build of a run.
type Environment struct {
	GoVersion  string `json:"go_version"`
	GOMAXPROCS int    `json:"gomaxprocs"`
	NumCPU     int    `json:"num_cpu"`
	CPUModel   string `json:"cpu_model"`
	LoadBefore string `json:"load_before"`
	LoadAfter  string `json:"load_after"`
	Commit     string `json:"commit"`
	Dirty      bool   `json:"dirty"`
	// BinaryRevision and BinaryModified come from the bench binary's embedded
	// VCS stamp: the code that measured, which may predate the checkout HEAD.
	BinaryRevision string `json:"binary_revision,omitempty"`
	BinaryModified bool   `json:"binary_modified,omitempty"`
}

// SidecarStats counts proxy traffic to the classifier.
type SidecarStats struct {
	Requests  int `json:"requests"`
	Upstream  int `json:"upstream"`
	CacheHits int `json:"cache_hits"`
	Misses    int `json:"cache_misses"`
	Failures  int `json:"failures"`
}

// JudgeStats counts proxy traffic to System One.
type JudgeStats struct {
	Requests      int     `json:"requests"`
	Upstream      int     `json:"upstream"`
	CacheHits     int     `json:"cache_hits"`
	Refused       int     `json:"refused"`
	EgressBlocked int     `json:"egress_blocked"`
	Failures      int     `json:"failures"`
	InputTokens   int64   `json:"input_tokens"`
	CostUSD       float64 `json:"cost_usd"`
	// UnknownBillingUSD is the worst case kept as spent for attempts whose
	// billing is unknown (transport failure, 5xx, unreadable answer).
	UnknownBillingUSD float64 `json:"unknown_billing_usd"`
	BodyBytes         int64   `json:"body_bytes"`
	StopReason        string  `json:"stop_reason,omitempty"`
}

// CaseResult is the outcome of one case. It never contains text.
type CaseResult struct {
	ID           string   `json:"id"`
	Lang         string   `json:"lang"`
	InputType    string   `json:"input_type"`
	Label        bool     `json:"label"`
	Status       string   `json:"status"`
	ErrorKind    string   `json:"error_kind,omitempty"`
	Decision     string   `json:"decision,omitempty"`
	Rules        bool     `json:"rules"`
	Semantic     bool     `json:"semantic"`
	SemanticRule string   `json:"semantic_rule,omitempty"`
	LatencyMS    float64  `json:"latency_ms"`
	Score        *float64 `json:"score,omitempty"`
	ModelMS      float64  `json:"model_ms,omitempty"`
	ModelCalls   int      `json:"model_calls,omitempty"`
	JudgeCalls   int      `json:"judge_calls,omitempty"`
	JudgeProb    *float64 `json:"judge_probability,omitempty"`
	JudgeMS      float64  `json:"judge_ms,omitempty"`
	JudgeTokens  int64    `json:"judge_input_tokens,omitempty"`
	JudgeCache   string   `json:"judge_cache,omitempty"`
}

// Status values of a case.
const (
	StatusOK    = "ok"
	StatusError = "error"
)

// RunFile is one pass of one configuration over one corpus.
type RunFile struct {
	Format            string         `json:"format"`
	Version           int            `json:"version"`
	RunID             string         `json:"run_id"`
	Mode              Mode           `json:"mode"`
	Model             string         `json:"model,omitempty"`
	Corpus            string         `json:"corpus"`
	CorpusSHA256      string         `json:"corpus_sha256"`
	ProtocolSHA256    string         `json:"protocol_sha256,omitempty"`
	SemanticThreshold *float64       `json:"semantic_threshold,omitempty"`
	Zone              *Zone          `json:"zone,omitempty"`
	Jev               *JevSettings   `json:"jev,omitempty"`
	SidecarReady      string         `json:"sidecar_ready,omitempty"`
	SidecarImage      string         `json:"sidecar_image,omitempty"`
	SidecarReplay     bool           `json:"sidecar_replay,omitempty"`
	ReplayDelay       bool           `json:"replay_delay,omitempty"`
	Environment       Environment    `json:"environment"`
	Started           string         `json:"started"`
	Finished          string         `json:"finished"`
	Concurrency       int            `json:"concurrency"`
	Warmup            []float64      `json:"warmup_ms"`
	Sidecar           *SidecarStats  `json:"sidecar,omitempty"`
	Judge             *JudgeStats    `json:"judge,omitempty"`
	Routes            map[string]int `json:"routes,omitempty"`
	Cases             []CaseResult   `json:"cases"`
}

// Bundle is the versioned, text-free export of every run used by a report.
type Bundle struct {
	Format         string    `json:"format"`
	Version        int       `json:"version"`
	ProtocolSHA256 string    `json:"protocol_sha256"`
	Runs           []RunFile `json:"runs"`
}

// WriteJSON writes v as indented JSON through a temporary file and rename.
func WriteJSON(path string, v any) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	if _, err := temporary.Write(buffer.Bytes()); err != nil {
		_ = temporary.Close()
		_ = os.Remove(temporary.Name())
		return err
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporary.Name())
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// ReadJSON decodes exactly one JSON value from path, rejecting unknown fields.
func ReadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: trailing data", path)
	}
	return nil
}

// FileSHA256 returns the hex sha256 of a file's bytes.
func FileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return BytesSHA256(data), nil
}

// BytesSHA256 returns the hex sha256 of data.
func BytesSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
