// Package loaders converts public evaluation datasets into the
// guardrail-eval corpus format (version 1).
//
// Nothing here runs automatically. An import is an explicit command that reads
// a local file or downloads one pinned URL whose SHA-256 digest is verified,
// and that writes only below a git-ignored directory. The datasets are never
// vendored in this repository.
package loaders

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

const (
	// MaxInputBytes bounds every dataset file read or downloaded.
	MaxInputBytes = 32 << 20

	// ScratchDir is the repository-local directory ignored by git where
	// imported corpora must be written.
	ScratchDir = ".agent-tmp"
)

// Dataset names a supported public dataset.
type Dataset string

const (
	BIPIA     Dataset = "bipia"
	AgentDojo Dataset = "agentdojo"
	Presidio  Dataset = "presidio"
)

// ParseDataset validates a dataset name.
func ParseDataset(value string) (Dataset, error) {
	switch Dataset(value) {
	case BIPIA, AgentDojo, Presidio:
		return Dataset(value), nil
	}
	return "", fmt.Errorf("dataset must be %q, %q or %q, got %q", BIPIA, AgentDojo, Presidio, value)
}

// Options are shared by all importers.
type Options struct {
	// Name is the corpus name; empty uses the dataset name.
	Name string
	// Limit keeps the first N cases in deterministic order; 0 keeps all.
	Limit int
	// Lang is the language code of the imported texts.
	Lang string
	// Source provenance, copied into the corpus header.
	Source eval.Source
	// Entities (Presidio only) lists the entity types mapped to detect_pii.
	Entities []string
}

// Skips counts source records that were not imported, by reason.
type Skips map[string]int

// Result is an imported corpus ready to be written.
type Result struct {
	Header eval.Header
	Cases  []eval.Case
	Skips  Skips
}

// Write encodes the corpus in the canonical format.
func (r *Result) Write(writer io.Writer) error { return eval.WriteCorpus(writer, r.Header, r.Cases) }

func (o Options) header(dataset Dataset, license, semantics string) eval.Header {
	name := o.Name
	if name == "" {
		name = string(dataset)
	}
	source := o.Source
	source.Dataset = string(dataset)
	return eval.Header{
		Name: name, License: license, LabelSemantics: semantics, Source: &source,
		Description: "Imported from the public " + string(dataset) + " dataset. Public data is not versioned in this repository.",
	}
}

func (o Options) lang(fallback string) string {
	if o.Lang != "" {
		return o.Lang
	}
	return fallback
}

// textID derives a stable, content-based case id so that re-importing a
// dataset revision yields the same ids whatever the file order.
func textID(prefix, text string) string {
	digest := sha256.Sum256([]byte(text))
	return prefix + "-" + hex.EncodeToString(digest[:])[:12]
}

var nonTagCharacters = regexp.MustCompile(`[^a-z0-9._-]+`)

// tag lowercases value into a valid corpus tag.
func tag(prefix, value string) string {
	slug := strings.Trim(nonTagCharacters.ReplaceAllString(strings.ToLower(value), "-"), "-.")
	if slug == "" {
		return prefix
	}
	if len(prefix)+1+len(slug) > 48 {
		slug = slug[:48-len(prefix)-1]
	}
	return prefix + "-" + slug
}

// collector keeps the first occurrence of each id, merges tags and applies
// the limit, so that results never depend on map iteration order.
type collector struct {
	limit int
	order []string
	cases map[string]*eval.Case
	tags  map[string]map[string]bool
	skips Skips
}

func newCollector(limit int) *collector {
	return &collector{limit: limit, cases: map[string]*eval.Case{}, tags: map[string]map[string]bool{}, skips: Skips{}}
}

func (c *collector) skip(reason string) { c.skips[reason]++ }

// add records a case, or merges the tags of a duplicate text.
func (c *collector) add(item eval.Case, tags ...string) {
	if _, ok := c.cases[item.ID]; ok {
		c.skip("duplicate_text")
		for _, t := range tags {
			c.tags[item.ID][t] = true
		}
		return
	}
	if c.limit > 0 && len(c.order) >= c.limit {
		c.skip("over_limit")
		return
	}
	c.cases[item.ID] = &item
	c.tags[item.ID] = map[string]bool{}
	for _, t := range tags {
		c.tags[item.ID][t] = true
	}
	c.order = append(c.order, item.ID)
}

func (c *collector) result(header eval.Header) (*Result, error) {
	out := &Result{Header: header, Skips: c.skips}
	for _, id := range c.order {
		item := *c.cases[id]
		item.Tags = sortedSet(c.tags[id])
		out.Cases = append(out.Cases, item)
	}
	if len(out.Cases) == 0 {
		return nil, fmt.Errorf("no importable case found (skipped: %s)", describe(c.skips))
	}
	return out, nil
}

// checkText reports why a text cannot become a case, or "".
func checkText(text string) string {
	switch {
	case strings.TrimSpace(text) == "":
		return "blank_text"
	case len([]rune(text)) > eval.MaxCaseRunes:
		return "too_long"
	}
	return ""
}

func describe(skips Skips) string {
	if len(skips) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(skips))
	for key := range skips {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, key := range keys {
		parts[i] = fmt.Sprintf("%s=%d", key, skips[key])
	}
	return strings.Join(parts, " ")
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// ReadLimited reads all of reader, failing when it exceeds MaxInputBytes.
func ReadLimited(reader io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", MaxInputBytes)
	}
	return data, nil
}

// SHA256Hex returns the hex SHA-256 digest of data.
func SHA256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

var (
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
)

// FetchRequest describes one explicit, pinned download.
type FetchRequest struct {
	URL string
	// SHA256 is the expected digest of the body (hex, required).
	SHA256 string
	// Revision is the commit the URL is pinned to; the URL must contain it.
	Revision string
}

func (r FetchRequest) validate() error {
	parsed, err := url.Parse(r.URL)
	switch {
	case err != nil || parsed.Scheme != "https" || parsed.Host == "":
		return errors.New("--url must be an absolute https URL")
	case parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "":
		return errors.New("--url must not contain credentials, a query or a fragment")
	case !sha256Pattern.MatchString(r.SHA256):
		return errors.New("--sha256 must be the 64-character lowercase hex digest of the file")
	case !revisionPattern.MatchString(r.Revision):
		return errors.New("--revision must be the commit hash (7 to 64 hex characters) the URL is pinned to")
	case !strings.Contains(strings.ToLower(r.URL), r.Revision):
		return errors.New("--url must contain --revision so that it cannot follow a moving branch")
	}
	return nil
}

// Fetch downloads a pinned file and verifies its digest. client may be nil.
func Fetch(ctx context.Context, client *http.Client, req FetchRequest) ([]byte, error) {
	if err := req.validate(); err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	limited := *client
	limited.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) > 3 || next.URL.Scheme != "https" {
			return errors.New("redirect refused")
		}
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "guardrail-eval-import/1")
	response, err := limited.Do(request)
	if err != nil {
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed: HTTP %d", response.StatusCode)
	}
	data, err := ReadLimited(response.Body)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	if got := SHA256Hex(data); got != req.SHA256 {
		return nil, fmt.Errorf("digest mismatch: downloaded file has sha256 %s, expected %s", got, req.SHA256)
	}
	return data, nil
}

// CheckOutputPath refuses to write an imported corpus anywhere it could be
// committed: the path must have a ScratchDir component unless allowAny is set,
// and the destination, once symbolic links are resolved, must stay inside that
// directory.
func CheckOutputPath(path string, allowAny bool) error {
	if path == "" {
		return errors.New("--output is required")
	}
	if allowAny {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	root := scratchRoot(abs)
	if root == "" {
		return fmt.Errorf("--output must be inside a %s directory (git-ignored); pass --allow-any-output if the destination is ignored by other means", ScratchDir)
	}
	// Nothing below a scratch directory that does not exist yet can be a link.
	if _, err := os.Lstat(root); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	// Resolve the longest existing prefix: the file itself when it exists,
	// otherwise its nearest existing parent. The rest does not exist yet.
	existing, rest := abs, ""
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return fmt.Errorf("cannot resolve --output %q", path)
		}
		rest = filepath.Join(filepath.Base(existing), rest)
		existing = parent
	}
	realExisting, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(realRoot, filepath.Join(realExisting, rest))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("--output resolves outside the %s directory through a symbolic link", ScratchDir)
	}
	return nil
}

// scratchRoot returns the path up to and including the first ScratchDir
// component of an absolute path, or "" when there is none.
func scratchRoot(abs string) string {
	parts := strings.Split(filepath.ToSlash(abs), "/")
	for index, part := range parts {
		if part == ScratchDir {
			return filepath.FromSlash(strings.Join(parts[:index+1], "/"))
		}
	}
	return ""
}

// decodeJSON decodes data as exactly one JSON value.
func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("unexpected data after the JSON value")
	}
	return nil
}
