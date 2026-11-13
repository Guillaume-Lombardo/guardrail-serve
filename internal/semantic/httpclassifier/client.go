// Package httpclassifier implements semantic.PromptInjectionDetector on top
// of an external HTTP sidecar serving a prompt-injection classifier.
package httpclassifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	"github.com/g1lom/guardrail-serve/internal/semantic"
)

var _ semantic.PromptInjectionDetector = (*Classifier)(nil)

const (
	reasonTriggered = "Potential prompt injection detected by HTTP classifier."
	reasonDegraded  = "HTTP classifier unavailable; failing open."
)

// Classifier calls one configured sidecar URL. It is safe for concurrent use.
type Classifier struct {
	cfg    settings
	client *http.Client
}

// New validates cfg and builds a Classifier. It performs no network call.
func New(cfg Config) (*Classifier, error) {
	resolved, err := cfg.resolve()
	if err != nil {
		return nil, fmt.Errorf("http classifier config: %w", err)
	}
	return &Classifier{cfg: resolved, client: newHTTPClient()}, nil
}

// newHTTPClient never follows redirects and never uses proxies from the
// environment, so the configured URL is the only host ever contacted.
func newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// DetectPromptInjection scores every text with the sidecar and reports the
// maximum score over all chunks of all texts. Empty and blank texts are not
// sent. See the package README for failure semantics.
func (c *Classifier) DetectPromptInjection(ctx context.Context, texts []string) (semantic.PromptInjectionAssessment, error) {
	score, topIndex, chunks, err := c.score(ctx, texts)
	if err != nil {
		return c.fail(err)
	}

	metadata := map[string]any{
		"classifier_format":    string(c.cfg.format),
		"classifier_chunks":    chunks,
		"classifier_threshold": c.cfg.threshold,
	}
	if chunks > 0 {
		metadata["classifier_top_text_index"] = topIndex
	}
	assessment := semantic.PromptInjectionAssessment{
		Triggered: score >= c.cfg.threshold,
		Score:     score,
		Model:     c.cfg.modelName,
		Metadata:  metadata,
	}
	if assessment.Triggered {
		assessment.Reason = reasonTriggered
	}
	return assessment, nil
}

// fail applies the failure mode. A cancelled caller context is always
// returned as an error: nobody is waiting for the answer.
func (c *Classifier) fail(failure *Error) (semantic.PromptInjectionAssessment, error) {
	if c.cfg.failureMode == FailClosed || failure.Kind == FailureCanceled {
		return semantic.PromptInjectionAssessment{}, failure
	}
	return semantic.PromptInjectionAssessment{
		Triggered: false,
		Score:     0,
		Reason:    reasonDegraded,
		Model:     c.cfg.modelName,
		Metadata: map[string]any{
			"classifier_format":   string(c.cfg.format),
			"classifier_degraded": true,
			"classifier_failure":  string(failure.Kind),
		},
	}, nil
}

func (c *Classifier) score(ctx context.Context, texts []string) (score float64, topIndex, chunkCount int, failure *Error) {
	chunks, ok := c.chunk(texts)
	if !ok {
		return 0, 0, 0, newError(FailureTooManyChunks)
	}
	if len(chunks) == 0 {
		return 0, 0, 0, nil
	}

	callCtx, cancel := context.WithTimeout(ctx, c.cfg.timeout)
	defer cancel()

	topIndex = chunks[0].textIndex
	for from := 0; from < len(chunks); from += c.cfg.batchSize {
		batch := chunks[from:min(from+c.cfg.batchSize, len(chunks))]
		scores, err := c.classify(callCtx, batch)
		if err != nil {
			return 0, 0, 0, toFailure(ctx, callCtx, err)
		}
		for i, value := range scores {
			if value > score {
				score, topIndex = value, batch[i].textIndex
			}
		}
	}
	return score, topIndex, len(chunks), nil
}

func (c *Classifier) chunk(texts []string) ([]chunk, bool) {
	var chunks []chunk
	for index, text := range texts {
		if strings.TrimSpace(text) == "" {
			continue
		}
		pieces, complete := splitRunes(text, c.cfg.chunkRunes, c.cfg.overlapRunes, c.cfg.maxChunks-len(chunks))
		for _, piece := range pieces {
			chunks = append(chunks, chunk{textIndex: index, text: piece})
		}
		if !complete {
			return nil, false
		}
	}
	return chunks, true
}

// classify sends one batch and returns one score per chunk, in order.
func (c *Classifier) classify(ctx context.Context, batch []chunk) ([]float64, error) {
	body, err := c.encode(batch)
	if err != nil {
		return nil, newError(FailureTransport)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, newError(FailureTransport)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, &Error{Kind: FailureStatus, Status: response.StatusCode}
	}
	if response.ContentLength > c.cfg.maxResponse {
		return nil, newError(FailureResponseTooLarge)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, c.cfg.maxResponse+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > c.cfg.maxResponse {
		return nil, newError(FailureResponseTooLarge)
	}
	return c.decode(payload, len(batch))
}

func (c *Classifier) encode(batch []chunk) ([]byte, error) {
	switch c.cfg.format {
	case FormatTEIPredict:
		inputs := make([][]string, len(batch))
		for i, item := range batch {
			// A one-element array is a single sequence; a bare list of two
			// strings would be read by TEI as one (query, text) pair.
			inputs[i] = []string{item.text}
		}
		return json.Marshal(struct {
			Inputs    [][]string `json:"inputs"`
			RawScores bool       `json:"raw_scores"`
			Truncate  bool       `json:"truncate"`
		}{Inputs: inputs})
	default:
		texts := make([]string, len(batch))
		for i, item := range batch {
			texts[i] = item.text
		}
		return json.Marshal(struct {
			Texts []string `json:"texts"`
		}{Texts: texts})
	}
}

func (c *Classifier) decode(payload []byte, want int) ([]float64, error) {
	switch c.cfg.format {
	case FormatTEIPredict:
		return decodeTEI(payload, want, c.cfg.labels)
	default:
		return decodeScores(payload, want)
	}
}

func decodeScores(payload []byte, want int) ([]float64, error) {
	var response struct {
		Scores []*float64 `json:"scores"`
	}
	if err := decodeJSON(payload, &response); err != nil {
		return nil, err
	}
	if len(response.Scores) != want {
		return nil, newError(FailureInvalidResponse)
	}
	scores := make([]float64, want)
	for i, value := range response.Scores {
		valid, err := checkScore(value)
		if err != nil {
			return nil, err
		}
		scores[i] = valid
	}
	return scores, nil
}

func decodeTEI(payload []byte, want int, labels []string) ([]float64, error) {
	var response [][]struct {
		Label *string  `json:"label"`
		Score *float64 `json:"score"`
	}
	if err := decodeJSON(payload, &response); err != nil {
		return nil, err
	}
	if len(response) != want {
		return nil, newError(FailureInvalidResponse)
	}
	scores := make([]float64, want)
	for i, predictions := range response {
		if len(predictions) == 0 {
			return nil, newError(FailureInvalidResponse)
		}
		found := false
		for _, prediction := range predictions {
			if prediction.Label == nil {
				return nil, newError(FailureInvalidResponse)
			}
			value, err := checkScore(prediction.Score)
			if err != nil {
				return nil, err
			}
			if matchesLabel(*prediction.Label, labels) {
				found = true
				scores[i] = max(scores[i], value)
			}
		}
		if !found {
			return nil, newError(FailureInvalidResponse)
		}
	}
	return scores, nil
}

func matchesLabel(label string, labels []string) bool {
	for _, candidate := range labels {
		if strings.EqualFold(strings.TrimSpace(label), candidate) {
			return true
		}
	}
	return false
}

// decodeJSON decodes exactly one JSON value; unknown fields are tolerated so
// sidecars can add fields, trailing data is not.
func decodeJSON(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(target); err != nil {
		return newError(FailureInvalidResponse)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return newError(FailureInvalidResponse)
	}
	return nil
}

func checkScore(value *float64) (float64, error) {
	if value == nil {
		return 0, newError(FailureInvalidResponse)
	}
	if math.IsNaN(*value) || math.IsInf(*value, 0) || *value < 0 || *value > 1 {
		return 0, newError(FailureInvalidScore)
	}
	return *value, nil
}
