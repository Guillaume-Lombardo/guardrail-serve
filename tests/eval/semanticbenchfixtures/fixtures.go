// Package semanticbenchfixtures loads and validates the semantic benchmark
// corpus (ADR 0022): two split corpora in the guardrail-eval format v1
// (calibration and test), a per-case metadata file and a manifest.
//
// It never runs a detector or a model. It is the contract the future benchmark
// runner reads: file names, manifest schema, taxonomy, denominators, and the
// invariants that keep calibration and test apart.
package semanticbenchfixtures

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
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

// Contract constants for the benchmark runner.
const (
	// Dir is the corpus directory relative to the repository root.
	Dir = "tests/eval/corpus/semantic-bench"
	// ManifestFile, MetadataFile are fixed names inside Dir. The corpus file
	// names come from the manifest (files.calibration.path, files.test.path).
	ManifestFile = "manifest.json"
	MetadataFile = "metadata.jsonl"

	ManifestFormat  = "guardrail-serve-semantic-bench-manifest"
	ManifestVersion = 1

	// Detector is the only detector labelled in the benchmark corpora.
	Detector = "prompt_injection"
	// Lang is the language of every case.
	Lang = "fr"

	// NearDuplicateThreshold is the character 5-gram Jaccard similarity of two
	// skeletons from which two texts count as near-duplicates. Paraphrases of
	// one template group score above it; unrelated texts score far below.
	NearDuplicateThreshold = 0.5

	maxFileBytes = 8 << 20
)

// Split names a corpus partition.
type Split string

const (
	// Calibration may be measured repeatedly to choose thresholds and models.
	Calibration Split = "calibration"
	// Test is frozen: measured once the configuration is fixed, reported only.
	Test Split = "test"
)

// Splits lists the splits in reading order.
func Splits() []Split { return []Split{Calibration, Test} }

// Class is the reference class of a case.
type Class string

const (
	Attack       Class = "attack"
	HardNegative Class = "hard_negative"
)

// FileEntry points to a file next to the manifest and pins its digest.
type FileEntry struct {
	Path   string `json:"path"`
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
}

// Family is one taxonomy entry.
type Family struct {
	Class       Class  `json:"class"`
	Description string `json:"description"`
}

// Taxonomy lists the classes and families of the benchmark.
type Taxonomy struct {
	Classes  []Class           `json:"classes"`
	Families map[string]Family `json:"families"`
}

// Source documents the provenance and license of a group of cases.
type Source struct {
	License            string `json:"license"`
	Kind               string `json:"kind"`
	Provenance         string `json:"provenance"`
	Synthetic          bool   `json:"synthetic"`
	ContainsRealData   bool   `json:"contains_real_data"`
	ContainsCredential bool   `json:"contains_credentials"`
}

// SetHashes pins the content of a split independently of file formatting.
type SetHashes struct {
	IDs            string `json:"ids_sha256"`
	Texts          string `json:"texts_sha256"`
	TemplateGroups string `json:"template_groups_sha256"`
}

// ClassCounts counts the cases of one family in a split.
type ClassCounts struct {
	Attack       int `json:"attack"`
	HardNegative int `json:"hard_negative"`
}

// Denominators are the counts a report must divide by.
type Denominators struct {
	Cases          int                    `json:"cases"`
	Attack         int                    `json:"attack"`
	HardNegative   int                    `json:"hard_negative"`
	TemplateGroups int                    `json:"template_groups"`
	ByFamily       map[string]ClassCounts `json:"by_family"`
	ByInputType    map[string]int         `json:"by_input_type"`
	ByTransform    map[string]int         `json:"by_transform"`
	BySource       map[string]int         `json:"by_source"`
}

// Manifest is the benchmark manifest (manifest.json).
type Manifest struct {
	Format         string                  `json:"format"`
	Version        int                     `json:"version"`
	Name           string                  `json:"name"`
	Created        string                  `json:"created"`
	Language       string                  `json:"language"`
	TargetDetector string                  `json:"target_detector"`
	Seed           int64                   `json:"seed"`
	Ordering       string                  `json:"ordering"`
	Files          map[string]FileEntry    `json:"files"`
	Usage          map[string]string       `json:"usage"`
	SplitPolicy    map[string]string       `json:"split_policy"`
	LabelPolicy    LabelPolicy             `json:"label_policy"`
	Taxonomy       Taxonomy                `json:"taxonomy"`
	Sources        map[string]Source       `json:"sources"`
	Sets           map[string]SetHashes    `json:"sets"`
	SetHashDefn    string                  `json:"set_hash_definition"`
	Denominators   map[string]Denominators `json:"denominators"`
}

// LabelPolicy states what a label means and how it was reviewed.
type LabelPolicy struct {
	Rule             string   `json:"rule"`
	Review           string   `json:"review"`
	LabelledDetector []string `json:"labelled_detectors"`
}

// Record is one line of metadata.jsonl: what the corpus format cannot carry.
type Record struct {
	ID            string `json:"id"`
	Split         Split  `json:"split"`
	Class         Class  `json:"class"`
	Family        string `json:"family"`
	TemplateGroup string `json:"template_group"`
	Source        string `json:"source"`
	Lang          string `json:"lang"`
	InputType     string `json:"input_type"`
	Transform     string `json:"transform"`
	DerivedFrom   string `json:"derived_from,omitempty"`
}

// Bundle is a loaded benchmark.
type Bundle struct {
	Manifest       Manifest
	Records        []Record
	Corpora        map[Split]*eval.Corpus
	MetadataSHA256 string
}

// Load reads the manifest, the metadata and both corpora from dir. Every file
// is decoded strictly; the corpus files go through eval.ParseCorpus, the same
// parser the HTTP harness uses.
func Load(dir string) (*Bundle, error) {
	var manifest Manifest
	manifestData, err := readFile(filepath.Join(dir, ManifestFile))
	if err != nil {
		return nil, err
	}
	if err := decodeStrict(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestFile, err)
	}

	bundle := &Bundle{Manifest: manifest, Corpora: map[Split]*eval.Corpus{}}
	for _, split := range Splits() {
		entry, ok := manifest.Files[string(split)]
		if !ok {
			return nil, fmt.Errorf("manifest has no files.%s entry", split)
		}
		name, err := safeName(entry.Path)
		if err != nil {
			return nil, fmt.Errorf("files.%s.path: %w", split, err)
		}
		data, err := readFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		corpus, err := eval.ParseCorpus(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		bundle.Corpora[split] = corpus
	}

	meta, ok := manifest.Files["metadata"]
	if !ok {
		return nil, errors.New("manifest has no files.metadata entry")
	}
	if meta.Path != MetadataFile {
		return nil, fmt.Errorf("files.metadata.path must be %q, got %q", MetadataFile, meta.Path)
	}
	metaData, err := readFile(filepath.Join(dir, MetadataFile))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(metaData)
	bundle.MetadataSHA256 = hex.EncodeToString(sum[:])
	for number, line := range bytes.Split(metaData, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var record Record
		if err := decodeStrict(line, &record); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", MetadataFile, number+1, err)
		}
		bundle.Records = append(bundle.Records, record)
	}
	return bundle, nil
}

func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maxFileBytes)
	}
	return data, nil
}

func decodeStrict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("unexpected data after the JSON value")
	}
	return nil
}

// safeName accepts a plain file name, never a path.
func safeName(name string) (string, error) {
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("%q must be a plain file name", name)
	}
	return name, nil
}

var (
	idPattern    = regexp.MustCompile(`^sb-[0-9]{4}$`)
	groupPattern = regexp.MustCompile(`^tg-[a-z]{3}-[0-9]{2}$`)
	// Licenses accepted for benchmark data: permissive, no share-alike.
	allowedLicenses = map[string]bool{"MIT": true, "Apache-2.0": true, "BSD-3-Clause": true, "CC0-1.0": true}
)

// Validate checks every invariant of the benchmark and returns all violations
// joined (nil when the bundle is sound). Messages cite case IDs, never texts.
func (b *Bundle) Validate() error {
	v := &violations{}
	b.validateManifest(v)
	cases := b.validateCases(v)
	b.validateTaxonomyAndSources(v)
	b.validateRecords(v, cases)
	b.validateSeparation(v)
	b.validateDigestsAndDenominators(v)
	return v.err()
}

type violations struct{ list []error }

func (v *violations) addf(format string, args ...any) {
	v.list = append(v.list, fmt.Errorf(format, args...))
}
func (v *violations) err() error { return errors.Join(v.list...) }

func (b *Bundle) validateManifest(v *violations) {
	m := b.Manifest
	switch {
	case m.Format != ManifestFormat:
		v.addf("manifest format %q, want %q", m.Format, ManifestFormat)
	case m.Version != ManifestVersion:
		v.addf("manifest version %d, want %d", m.Version, ManifestVersion)
	case m.TargetDetector != Detector:
		v.addf("manifest target_detector %q, want %q", m.TargetDetector, Detector)
	case m.Language != Lang:
		v.addf("manifest language %q, want %q", m.Language, Lang)
	}
	if m.Seed == 0 {
		v.addf("manifest seed is missing")
	}
	for _, key := range []string{"calibration", "test", "metadata"} {
		entry, ok := m.Files[key]
		if !ok || entry.Role != key || len(entry.SHA256) != 64 {
			v.addf("manifest files.%s is missing, has the wrong role or has no sha256", key)
		}
	}
	if len(m.Files) != 3 {
		v.addf("manifest lists %d files, want calibration, test and metadata", len(m.Files))
	}
	for _, split := range Splits() {
		if strings.TrimSpace(m.Usage[string(split)]) == "" {
			v.addf("manifest usage.%s is empty", split)
		}
		if _, ok := m.Sets[string(split)]; !ok {
			v.addf("manifest sets.%s is missing", split)
		}
		if _, ok := m.Denominators[string(split)]; !ok {
			v.addf("manifest denominators.%s is missing", split)
		}
	}
	if _, ok := m.Denominators["total"]; !ok {
		v.addf("manifest denominators.total is missing")
	}
	if !equalStrings(m.LabelPolicy.LabelledDetector, []string{Detector}) {
		v.addf("manifest label_policy.labelled_detectors must be [%q]", Detector)
	}
}

// caseInfo joins a corpus case with its split.
type caseInfo struct {
	eval.Case
	Split Split
}

// validateCases checks the corpus files and returns their cases by ID.
func (b *Bundle) validateCases(v *violations) map[string]caseInfo {
	cases := map[string]caseInfo{}
	for _, split := range Splits() {
		corpus := b.Corpora[split]
		if corpus == nil {
			v.addf("split %s has no corpus", split)
			continue
		}
		if want := b.Manifest.Files[string(split)].SHA256; corpus.SHA256 != want {
			v.addf("split %s: file sha256 %s differs from the manifest", split, corpus.SHA256)
		}
		for _, item := range corpus.Cases {
			if !idPattern.MatchString(item.ID) {
				v.addf("case %s: id must match %s", item.ID, idPattern)
			}
			if _, dup := cases[item.ID]; dup {
				v.addf("case %s appears in both splits or twice", item.ID)
			}
			cases[item.ID] = caseInfo{Case: item, Split: split}
			if item.Lang != Lang {
				v.addf("case %s: lang %q, want %q", item.ID, item.Lang, Lang)
			}
			if len(item.Labels) != 1 {
				v.addf("case %s: exactly one label (%s) is expected", item.ID, Detector)
			} else if _, ok := item.Labels[Detector]; !ok {
				v.addf("case %s: missing label %s", item.ID, Detector)
			}
		}
	}
	return cases
}

func (b *Bundle) validateTaxonomyAndSources(v *violations) {
	t := b.Manifest.Taxonomy
	if !equalStrings(classNames(t.Classes), []string{string(Attack), string(HardNegative)}) {
		v.addf("taxonomy classes must be [attack hard_negative], got %v", t.Classes)
	}
	for name, family := range t.Families {
		if family.Class != Attack && family.Class != HardNegative {
			v.addf("family %s: unknown class %q", name, family.Class)
		}
		if strings.TrimSpace(family.Description) == "" {
			v.addf("family %s: empty description", name)
		}
	}
	for name, source := range b.Manifest.Sources {
		switch {
		case !allowedLicenses[source.License]:
			v.addf("source %s: license %q is not in the permissive allow-list", name, source.License)
		case strings.TrimSpace(source.Provenance) == "" || strings.TrimSpace(source.Kind) == "":
			v.addf("source %s: provenance and kind are required", name)
		case !source.Synthetic || source.ContainsRealData || source.ContainsCredential:
			v.addf("source %s: must be synthetic, with no real data and no credentials", name)
		}
	}
}

func (b *Bundle) validateRecords(v *violations, cases map[string]caseInfo) {
	records := map[string]Record{}
	for _, r := range b.Records {
		if _, dup := records[r.ID]; dup {
			v.addf("metadata: duplicate record %s", r.ID)
		}
		records[r.ID] = r
	}
	for id := range cases {
		if _, ok := records[id]; !ok {
			v.addf("case %s has no metadata record", id)
		}
	}
	for _, r := range b.Records {
		item, ok := cases[r.ID]
		if !ok {
			v.addf("metadata record %s has no corpus case", r.ID)
			continue
		}
		b.validateRecord(v, r, item, records)
	}
}

func (b *Bundle) validateRecord(v *violations, r Record, item caseInfo, records map[string]Record) {
	if r.Split != item.Split {
		v.addf("case %s: metadata split %s, stored in %s", r.ID, r.Split, item.Split)
	}
	if r.Lang != item.Lang || r.InputType != string(item.InputType) {
		v.addf("case %s: metadata lang/input_type differ from the corpus", r.ID)
	}
	wantClass := HardNegative
	if item.Labels[Detector] {
		wantClass = Attack
	}
	if r.Class != wantClass {
		v.addf("case %s: class %s contradicts label %s=%t", r.ID, r.Class, Detector, item.Labels[Detector])
	}
	family, ok := b.Manifest.Taxonomy.Families[r.Family]
	switch {
	case !ok:
		v.addf("case %s: family %q is not in the taxonomy", r.ID, r.Family)
	case family.Class != r.Class:
		v.addf("case %s: family %s is a %s family, case is %s", r.ID, r.Family, family.Class, r.Class)
	}
	if len(item.Tags) == 0 || item.Tags[0] != r.Family {
		v.addf("case %s: first tag must be the family %q", r.ID, r.Family)
	}
	if !groupPattern.MatchString(r.TemplateGroup) {
		v.addf("case %s: template_group %q must match %s", r.ID, r.TemplateGroup, groupPattern)
	}
	if _, ok := b.Manifest.Sources[r.Source]; !ok {
		v.addf("case %s: source %q is not declared in the manifest", r.ID, r.Source)
	}
	if r.Transform == "" {
		v.addf("case %s: transform is empty (use \"none\")", r.ID)
	} else if (r.Transform != "none") != contains(item.Tags[min(1, len(item.Tags)):], r.Transform) {
		v.addf("case %s: transform %q and tags %v disagree", r.ID, r.Transform, item.Tags)
	}
	if r.DerivedFrom == "" {
		return
	}
	base, ok := records[r.DerivedFrom]
	switch {
	case !ok:
		v.addf("case %s: derived_from %s does not exist", r.ID, r.DerivedFrom)
	case base.Split != r.Split || base.TemplateGroup != r.TemplateGroup:
		v.addf("case %s: derived_from %s must share split and template group", r.ID, r.DerivedFrom)
	case base.DerivedFrom != "" || base.Transform != "none":
		v.addf("case %s: derived_from %s must be an untransformed base", r.ID, r.DerivedFrom)
	}
	if r.Transform == "none" || b.Manifest.Sources[r.Source].Kind != "mechanical-transform" {
		v.addf("case %s: a derived case needs a transform and a mechanical-transform source", r.ID)
	}
}

// validateSeparation enforces the calibration/test separation: whole template
// groups, no exact, normalised or near-duplicate text across the splits.
func (b *Bundle) validateSeparation(v *violations) {
	groupSplit := map[string]Split{}
	for _, r := range b.Records {
		if first, seen := groupSplit[r.TemplateGroup]; seen && first != r.Split {
			v.addf("template group %s spans splits %s and %s", r.TemplateGroup, first, r.Split)
		}
		groupSplit[r.TemplateGroup] = r.Split
	}
	for _, o := range Overlaps(b.Corpora[Calibration], b.Corpora[Test], NearDuplicateThreshold) {
		v.addf("calibration %s and test %s overlap: %s", o.A, o.B, o.Kind)
	}
}

func (b *Bundle) validateDigestsAndDenominators(v *violations) {
	if want := b.Manifest.Files["metadata"].SHA256; b.MetadataSHA256 != want {
		v.addf("metadata sha256 %s differs from the manifest", b.MetadataSHA256)
	}
	byID := map[string]Record{}
	for _, r := range b.Records {
		byID[r.ID] = r
	}
	var all []Record
	for _, split := range Splits() {
		corpus := b.Corpora[split]
		if corpus == nil {
			continue
		}
		var subset []Record
		var ids, hashes, groups []string
		for _, item := range corpus.Cases {
			ids = append(ids, item.ID)
			sum := sha256.Sum256([]byte(item.Text))
			hashes = append(hashes, hex.EncodeToString(sum[:]))
			if r, ok := byID[item.ID]; ok {
				subset = append(subset, r)
				groups = append(groups, r.TemplateGroup)
			}
		}
		all = append(all, subset...)
		want := b.Manifest.Sets[string(split)]
		got := SetHashes{IDs: SetDigest(ids), Texts: SetDigest(hashes), TemplateGroups: SetDigest(unique(groups))}
		if got != want {
			v.addf("split %s: set hashes differ from the manifest (ids, texts or template groups changed)", split)
		}
		if !sameDenominators(Count(subset), b.Manifest.Denominators[string(split)]) {
			v.addf("split %s: denominators differ from the manifest", split)
		}
	}
	if !sameDenominators(Count(all), b.Manifest.Denominators["total"]) {
		v.addf("total denominators differ from the manifest")
	}
	// Every family needs samples in both splits, or its per-family table is empty.
	for name := range b.Manifest.Taxonomy.Families {
		for _, split := range Splits() {
			counts := b.Manifest.Denominators[string(split)].ByFamily[name]
			if counts.Attack+counts.HardNegative == 0 {
				v.addf("family %s has no samples in split %s", name, split)
			}
		}
	}
	for _, split := range Splits() {
		d := b.Manifest.Denominators[string(split)]
		if d.Attack != d.HardNegative {
			v.addf("split %s is not class balanced: %d attacks, %d hard negatives", split, d.Attack, d.HardNegative)
		}
	}
}

// Count computes the denominators of a set of records.
func Count(records []Record) Denominators {
	d := Denominators{ByFamily: map[string]ClassCounts{}, ByInputType: map[string]int{}, ByTransform: map[string]int{}, BySource: map[string]int{}}
	groups := map[string]bool{}
	for _, r := range records {
		d.Cases++
		groups[r.TemplateGroup] = true
		counts := d.ByFamily[r.Family]
		if r.Class == Attack {
			d.Attack++
			counts.Attack++
		} else {
			d.HardNegative++
			counts.HardNegative++
		}
		d.ByFamily[r.Family] = counts
		d.ByInputType[r.InputType]++
		d.ByTransform[r.Transform]++
		d.BySource[r.Source]++
	}
	d.TemplateGroups = len(groups)
	return d
}

func sameDenominators(a, b Denominators) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

// SetDigest is the manifest's set hash: SHA-256 of the sorted items, each
// followed by a newline.
func SetDigest(items []string) string {
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n") + "\n"))
	return hex.EncodeToString(sum[:])
}

// Overlap is a pair of cases that are too similar to sit in two corpora.
type Overlap struct {
	A, B string
	Kind string // "exact", "skeleton" or "near-duplicate (0.NN)"
}

// Overlaps compares every case of a with every case of b. Exact equality,
// equal skeletons (see Skeleton) and a skeleton similarity at or above
// threshold are reported. IDs only: texts are not copied into messages.
func Overlaps(a, b *eval.Corpus, threshold float64) []Overlap {
	if a == nil || b == nil {
		return nil
	}
	type prepared struct {
		id, text, skeleton string
		grams              map[string]bool
	}
	prepare := func(c *eval.Corpus) []prepared {
		out := make([]prepared, 0, len(c.Cases))
		for _, item := range c.Cases {
			s := Skeleton(item.Text)
			out = append(out, prepared{item.ID, item.Text, s, ngrams(s)})
		}
		return out
	}
	left, right := prepare(a), prepare(b)
	var found []Overlap
	for _, x := range left {
		for _, y := range right {
			switch {
			case x.text == y.text:
				found = append(found, Overlap{x.id, y.id, "exact"})
			case x.skeleton == y.skeleton:
				found = append(found, Overlap{x.id, y.id, "skeleton"})
			default:
				if score := jaccard(x.grams, y.grams); score >= threshold {
					found = append(found, Overlap{x.id, y.id, fmt.Sprintf("near-duplicate (%.2f)", score)})
				}
			}
		}
	}
	return found
}

// Similarity is the character 5-gram Jaccard similarity of two skeletons.
func Similarity(a, b string) float64 { return jaccard(ngrams(Skeleton(a)), ngrams(Skeleton(b))) }

const gramSize = 5

func ngrams(s string) map[string]bool {
	runes := []rune(s)
	grams := map[string]bool{}
	if len(runes) <= gramSize {
		grams[s] = true
		return grams
	}
	for i := 0; i+gramSize <= len(runes); i++ {
		grams[string(runes[i:i+gramSize])] = true
	}
	return grams
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	shared := 0
	for gram := range a {
		if b[gram] {
			shared++
		}
	}
	return float64(shared) / float64(len(a)+len(b)-shared)
}

var (
	// fold maps accented French letters and the Cyrillic and Greek letters
	// commonly used as Latin homoglyphs to their Latin base, and decodes the
	// usual leet digits. It is a similarity tool, not a security control.
	fold = map[rune]string{
		'à': "a", 'â': "a", 'ä': "a", 'á': "a", 'ç': "c", 'é': "e", 'è': "e", 'ê': "e", 'ë': "e",
		'î': "i", 'ï': "i", 'í': "i", 'ô': "o", 'ö': "o", 'ó': "o", 'ù': "u", 'û': "u", 'ü': "u", 'ú': "u",
		'ÿ': "y", 'œ': "oe", 'æ': "ae", 'ñ': "n",
		'а': "a", 'в': "b", 'е': "e", 'к': "k", 'м': "m", 'н': "h", 'о': "o", 'р': "p", 'с': "c", 'т': "t",
		'у': "y", 'х': "x", 'і': "i", 'ѕ': "s", 'ј': "j", 'ο': "o", 'α': "a", 'ε': "e", 'ι': "i", 'ρ': "p",
		'0': "o", '1': "i", '3': "e", '4': "a", '5': "s", '7': "t", '@': "a", '$': "s",
	}
)

// Skeleton reduces a text to a comparison form: lower case, accents,
// homoglyphs and leet digits folded, zero-width and format characters, spaces
// and punctuation removed. Texts that differ only by those transformations
// share a skeleton.
func Skeleton(text string) string {
	var out strings.Builder
	for _, r := range text {
		r = unicode.ToLower(r)
		if mapped, ok := fold[r]; ok {
			out.WriteString(mapped)
			continue
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func equalStrings(a, b []string) bool {
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

func classNames(classes []Class) []string {
	names := make([]string, len(classes))
	for i, c := range classes {
		names[i] = string(c)
	}
	return names
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func unique(items []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}
