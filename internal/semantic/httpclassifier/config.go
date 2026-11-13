package httpclassifier

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

// Format selects the wire contract spoken by the sidecar.
type Format string

const (
	// FormatScores is the minimal contract defined by this package:
	// request {"texts": [...]}, response {"scores": [...]} with one score
	// in [0, 1] per text, in order.
	FormatScores Format = "scores"
	// FormatTEIPredict is the Hugging Face Text Embeddings Inference
	// POST /predict contract for sequence classification models.
	FormatTEIPredict Format = "tei_predict"
)

// ParseFormat converts a user-facing value into a Format.
func ParseFormat(value string) (Format, error) {
	switch format := Format(strings.TrimSpace(value)); format {
	case FormatScores, FormatTEIPredict:
		return format, nil
	default:
		return "", fmt.Errorf("unsupported classifier format %q (expected %q or %q)", value, FormatScores, FormatTEIPredict)
	}
}

func (f Format) String() string { return string(f) }

// FailureMode decides what a classifier failure means for the caller.
type FailureMode string

const (
	// FailClosed returns the failure as an error: the caller never gets a
	// successful assessment when the classifier did not produce a score.
	FailClosed FailureMode = "closed"
	// FailOpen converts a classifier failure into a non-triggered
	// assessment that is explicitly marked as degraded in its metadata.
	FailOpen FailureMode = "open"
)

// ParseFailureMode converts a user-facing value into a FailureMode.
func ParseFailureMode(value string) (FailureMode, error) {
	switch mode := FailureMode(strings.TrimSpace(value)); mode {
	case FailClosed, FailOpen:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported failure mode %q (expected %q or %q)", value, FailClosed, FailOpen)
	}
}

func (m FailureMode) String() string { return string(m) }

const (
	// DefaultModelName is reported in assessments when Config.ModelName is empty.
	DefaultModelName = "http-classifier"
	// DefaultMaliciousLabel is the label scored as an attack with FormatTEIPredict.
	DefaultMaliciousLabel = "MALICIOUS"
	// DefaultMaxResponseBytes bounds how much of a response body is read.
	DefaultMaxResponseBytes int64 = 1 << 20
	// DefaultChunkRunes is the largest chunk, in runes. Prompt Guard 2 has a
	// 512-token window and two of those tokens are special tokens; this
	// assumes about one token per rune at most, a heuristic (no tokenizer is
	// available) that leaves a wide margin for ordinary text.
	DefaultChunkRunes = 510
	// DefaultChunkOverlapRunes is the overlap between consecutive chunks.
	DefaultChunkOverlapRunes = 64
	// DefaultBatchSize matches the default max client batch size of TEI.
	DefaultBatchSize = 32
	// DefaultMaxChunks bounds the classifier calls issued for one detection.
	DefaultMaxChunks = 256

	minChunkRunes = 16
)

// Config is the complete constructor input. Nothing is read from the
// environment; zero values select documented defaults only for fields
// marked optional.
type Config struct {
	// URL is the sidecar endpoint (required): absolute http or https URL
	// without user info or fragment. It is the only address ever contacted.
	URL string
	// Format selects the wire contract (required).
	Format Format
	// Threshold in (0, 1] (required). A score greater than or equal to it
	// triggers the assessment.
	Threshold float64
	// Timeout bounds one whole detection, all HTTP calls included (required, > 0).
	Timeout time.Duration
	// FailureMode is required: there is no implicit fail-open or fail-closed.
	FailureMode FailureMode

	// ModelName is reported as Assessment.Model (optional).
	ModelName string
	// MaliciousLabels are the labels scored as an attack with
	// FormatTEIPredict, matched case-insensitively (optional, default
	// [DefaultMaliciousLabel]). Ignored by FormatScores.
	MaliciousLabels []string
	// MaxResponseBytes bounds a response body (optional, default 1 MiB).
	MaxResponseBytes int64
	// ChunkRunes is the maximum chunk size in runes (optional, default 510).
	ChunkRunes int
	// ChunkOverlapRunes is the overlap between consecutive chunks (optional,
	// zero selects min(64, ChunkRunes/4); must not exceed ChunkRunes/4).
	ChunkOverlapRunes int
	// BatchSize is the maximum number of chunks per HTTP call (optional,
	// default 32).
	BatchSize int
	// MaxChunks is the maximum number of chunks per detection (optional,
	// default 256). Larger inputs fail instead of being truncated.
	MaxChunks int
}

type settings struct {
	endpoint     string
	format       Format
	threshold    float64
	timeout      time.Duration
	failureMode  FailureMode
	modelName    string
	labels       []string
	maxResponse  int64
	chunkRunes   int
	overlapRunes int
	batchSize    int
	maxChunks    int
}

func (c Config) resolve() (settings, error) {
	endpoint, err := validateURL(c.URL)
	if err != nil {
		return settings{}, err
	}
	format, err := ParseFormat(string(c.Format))
	if err != nil {
		return settings{}, err
	}
	failureMode, err := ParseFailureMode(string(c.FailureMode))
	if err != nil {
		return settings{}, err
	}
	if math.IsNaN(c.Threshold) || c.Threshold <= 0 || c.Threshold > 1 {
		return settings{}, errors.New("threshold must be in (0, 1]")
	}
	if c.Timeout <= 0 {
		return settings{}, errors.New("timeout must be positive")
	}

	resolved := settings{
		endpoint:     endpoint,
		format:       format,
		threshold:    c.Threshold,
		timeout:      c.Timeout,
		failureMode:  failureMode,
		modelName:    strings.TrimSpace(c.ModelName),
		maxResponse:  c.MaxResponseBytes,
		chunkRunes:   c.ChunkRunes,
		overlapRunes: c.ChunkOverlapRunes,
		batchSize:    c.BatchSize,
		maxChunks:    c.MaxChunks,
	}
	if resolved.modelName == "" {
		resolved.modelName = DefaultModelName
	}
	if resolved.maxResponse == 0 {
		resolved.maxResponse = DefaultMaxResponseBytes
	}
	if resolved.chunkRunes == 0 {
		resolved.chunkRunes = DefaultChunkRunes
	}
	if resolved.overlapRunes == 0 {
		resolved.overlapRunes = min(DefaultChunkOverlapRunes, resolved.chunkRunes/4)
	}
	if resolved.batchSize == 0 {
		resolved.batchSize = DefaultBatchSize
	}
	if resolved.maxChunks == 0 {
		resolved.maxChunks = DefaultMaxChunks
	}

	if resolved.maxResponse < 0 {
		return settings{}, errors.New("max response bytes must be positive")
	}
	if resolved.chunkRunes < minChunkRunes {
		return settings{}, fmt.Errorf("chunk size must be at least %d runes", minChunkRunes)
	}
	if resolved.overlapRunes < 0 || resolved.overlapRunes > resolved.chunkRunes/4 {
		return settings{}, errors.New("chunk overlap must be between 0 and a quarter of the chunk size")
	}
	if resolved.batchSize < 0 || resolved.maxChunks < 0 {
		return settings{}, errors.New("batch size and max chunks must be positive")
	}

	labels := c.MaliciousLabels
	if len(labels) == 0 {
		labels = []string{DefaultMaliciousLabel}
	}
	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" {
			return settings{}, errors.New("malicious labels must not be empty")
		}
		resolved.labels = append(resolved.labels, label)
	}
	return resolved, nil
}

func validateURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("classifier URL is not a valid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("classifier URL must use http or https")
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("classifier URL must include a host")
	}
	if parsed.User != nil {
		return "", errors.New("classifier URL must not embed credentials")
	}
	if parsed.Fragment != "" {
		return "", errors.New("classifier URL must not include a fragment")
	}
	return parsed.String(), nil
}
