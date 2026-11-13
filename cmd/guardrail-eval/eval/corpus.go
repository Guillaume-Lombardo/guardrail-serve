package eval

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Corpus file contract (version 1).
//
// A corpus is a JSON Lines file. The first line is the header and every
// following line is one case. Records are decoded strictly: unknown fields are
// errors, so a typo cannot silently drop a label.
const (
	// CorpusFormat identifies the file type in the header.
	CorpusFormat = "guardrail-eval-corpus"
	// CorpusVersion is the only supported corpus contract version.
	CorpusVersion = 1

	// MaxCaseRunes mirrors the default MAX_TEXT_CHARS of the service so that a
	// case never trips the payload limits of a default deployment.
	MaxCaseRunes = 20000

	maxCorpusBytes = 64 << 20
	maxLineBytes   = 4 * (MaxCaseRunes + 4096)
	maxTags        = 16
	maxLabels      = 32
)

// InputType is the guardrail execution scope sent to the service.
type InputType string

const (
	InputRequest  InputType = "request"
	InputResponse InputType = "response"
)

// ParseInputType validates an input type; the empty string means request.
func ParseInputType(value string) (InputType, error) {
	switch InputType(value) {
	case "", InputRequest:
		return InputRequest, nil
	case InputResponse:
		return InputResponse, nil
	}
	return "", fmt.Errorf("input_type must be %q or %q, got %q", InputRequest, InputResponse, value)
}

// Source documents where an imported corpus comes from. Original corpora
// leave it empty.
type Source struct {
	Dataset  string `json:"dataset"`
	URL      string `json:"url,omitempty"`
	Revision string `json:"revision,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
}

// Header is the first record of a corpus file.
type Header struct {
	Format         string  `json:"format"`
	Version        int     `json:"version"`
	Name           string  `json:"name"`
	Description    string  `json:"description,omitempty"`
	License        string  `json:"license,omitempty"`
	LabelSemantics string  `json:"label_semantics,omitempty"`
	Source         *Source `json:"source,omitempty"`
}

// Case is one text with its expected detections.
//
// Labels maps a detector name to whether the text must be detected by that
// detector. A detector absent from Labels is not evaluated for the case, so
// corpora can label only what their source actually annotates.
type Case struct {
	ID        string          `json:"id"`
	Lang      string          `json:"lang"`
	InputType InputType       `json:"input_type,omitempty"`
	Text      string          `json:"text"`
	Labels    map[string]bool `json:"labels"`
	Tags      []string        `json:"tags,omitempty"`
}

// Corpus is a validated corpus plus the digest of its file.
type Corpus struct {
	Header Header
	Cases  []Case
	// SHA256 is the hex digest of the exact bytes that were parsed.
	SHA256 string
}

var (
	namePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	idPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
	langPattern     = regexp.MustCompile(`^[a-z]{2,3}$`)
	detectorPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	tagPattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,47}$`)
)

// LoadCorpus reads and validates a corpus file.
func LoadCorpus(path string) (*Corpus, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open corpus: %w", err)
	}
	defer file.Close()

	corpus, err := ParseCorpus(file)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return corpus, nil
}

// ParseCorpus reads and validates a corpus. Errors carry the 1-based line.
func ParseCorpus(reader io.Reader) (*Corpus, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxCorpusBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read corpus: %w", err)
	}
	if len(data) > maxCorpusBytes {
		return nil, fmt.Errorf("corpus exceeds %d bytes", maxCorpusBytes)
	}
	digest := sha256.Sum256(data)
	corpus := &Corpus{SHA256: hex.EncodeToString(digest[:])}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	seen := map[string]int{}
	line, haveHeader := 0, false
	for scanner.Scan() {
		line++
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		if !haveHeader {
			if err := decodeStrict(raw, &corpus.Header); err != nil {
				return nil, fmt.Errorf("line %d: header: %w", line, err)
			}
			if err := corpus.Header.validate(); err != nil {
				return nil, fmt.Errorf("line %d: header: %w", line, err)
			}
			haveHeader = true
			continue
		}
		var c Case
		if err := decodeStrict(raw, &c); err != nil {
			return nil, fmt.Errorf("line %d: case: %w", line, err)
		}
		if err := requireBooleanLabels(raw); err != nil {
			return nil, fmt.Errorf("line %d: case %q: %w", line, c.ID, err)
		}
		if err := c.normalize(); err != nil {
			return nil, fmt.Errorf("line %d: case %q: %w", line, c.ID, err)
		}
		if first, dup := seen[c.ID]; dup {
			return nil, fmt.Errorf("line %d: duplicate case id %q (first on line %d)", line, c.ID, first)
		}
		seen[c.ID] = line
		corpus.Cases = append(corpus.Cases, c)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	if !haveHeader {
		return nil, errors.New("empty corpus: missing header line")
	}
	if len(corpus.Cases) == 0 {
		return nil, errors.New("corpus has no cases")
	}
	return corpus, nil
}

// requireBooleanLabels rejects a null label, which would otherwise decode to
// false and silently become a negative reference.
func requireBooleanLabels(raw []byte) error {
	var probe struct {
		Labels map[string]json.RawMessage `json:"labels"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return err
	}
	for detector, value := range probe.Labels {
		if string(bytes.TrimSpace(value)) == "null" {
			return fmt.Errorf("label for %q must be true or false, got null", detector)
		}
	}
	return nil
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("unexpected data after the JSON object")
	}
	return nil
}

func (h Header) validate() error {
	switch {
	case h.Format != CorpusFormat:
		return fmt.Errorf("format must be %q, got %q", CorpusFormat, h.Format)
	case h.Version != CorpusVersion:
		return fmt.Errorf("unsupported corpus version %d (supported: %d)", h.Version, CorpusVersion)
	case !namePattern.MatchString(h.Name):
		return fmt.Errorf("name %q must match %s", h.Name, namePattern)
	case h.Source != nil && strings.TrimSpace(h.Source.Dataset) == "":
		return errors.New("source.dataset must not be empty")
	}
	return nil
}

// normalize applies defaults and validates the case.
func (c *Case) normalize() error {
	if !idPattern.MatchString(c.ID) {
		return fmt.Errorf("id must match %s", idPattern)
	}
	if !langPattern.MatchString(c.Lang) {
		return fmt.Errorf("lang %q must match %s", c.Lang, langPattern)
	}
	inputType, err := ParseInputType(string(c.InputType))
	if err != nil {
		return err
	}
	c.InputType = inputType
	if strings.TrimSpace(c.Text) == "" {
		return errors.New("text must not be blank")
	}
	if !utf8.ValidString(c.Text) {
		return errors.New("text must be valid UTF-8")
	}
	if n := utf8.RuneCountInString(c.Text); n > MaxCaseRunes {
		return fmt.Errorf("text has %d characters, limit is %d", n, MaxCaseRunes)
	}
	if len(c.Labels) == 0 || len(c.Labels) > maxLabels {
		return fmt.Errorf("labels must contain 1 to %d detectors", maxLabels)
	}
	for detector := range c.Labels {
		if !detectorPattern.MatchString(detector) {
			return fmt.Errorf("label detector %q must match %s", detector, detectorPattern)
		}
	}
	if len(c.Tags) > maxTags {
		return fmt.Errorf("at most %d tags", maxTags)
	}
	tags := map[string]bool{}
	for _, tag := range c.Tags {
		if !tagPattern.MatchString(tag) {
			return fmt.Errorf("tag %q must match %s", tag, tagPattern)
		}
		if tags[tag] {
			return fmt.Errorf("duplicate tag %q", tag)
		}
		tags[tag] = true
	}
	return nil
}

// Detectors lists the detector names labelled anywhere in the corpus.
func (c *Corpus) Detectors() []string {
	set := map[string]bool{}
	for _, item := range c.Cases {
		for detector := range item.Labels {
			set[detector] = true
		}
	}
	return sortedKeys(set)
}

// WriteCorpus validates and writes a corpus as JSON Lines, one record per
// line, with stable key order and no HTML escaping.
func WriteCorpus(writer io.Writer, header Header, cases []Case) error {
	header.Format, header.Version = CorpusFormat, CorpusVersion
	if err := header.validate(); err != nil {
		return fmt.Errorf("header: %w", err)
	}
	if len(cases) == 0 {
		return errors.New("corpus has no cases")
	}
	seen := map[string]bool{}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(header); err != nil {
		return err
	}
	for _, item := range cases {
		if err := item.normalize(); err != nil {
			return fmt.Errorf("case %q: %w", item.ID, err)
		}
		if seen[item.ID] {
			return fmt.Errorf("duplicate case id %q", item.ID)
		}
		seen[item.ID] = true
		if err := encoder.Encode(item); err != nil {
			return err
		}
	}
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
