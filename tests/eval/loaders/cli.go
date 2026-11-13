package loaders

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-eval/eval"
)

// Exit codes of the import command.
const (
	ExitOK      = 0
	ExitFailure = 1
	ExitUsage   = 2
)

const usageText = `Usage:
  eval-import --dataset bipia|agentdojo|presidio (--input PATH... | --url URL --sha256 HEX --revision COMMIT) --output FILE [options]

Converts a public dataset into a guardrail-eval corpus. Nothing is downloaded
unless --url is given, and the download must match --sha256. The output must be
inside a ` + ScratchDir + ` directory (git-ignored) unless --allow-any-output is set.
`

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// Main runs the import command and returns the process exit code.
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("eval-import", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { fmt.Fprint(stderr, usageText); flags.PrintDefaults() }
	var (
		dataset, output, name, lang, entities string
		fetch                                 FetchRequest
		inputs                                stringList
		limit                                 int
		allowAny                              bool
		timeout                               time.Duration
	)
	flags.StringVar(&dataset, "dataset", "", "bipia, agentdojo or presidio")
	flags.Var(&inputs, "input", "local dataset file (repeatable; AgentDojo also accepts directories of run traces)")
	flags.StringVar(&fetch.URL, "url", "", "pinned https URL of one dataset file (explicit download)")
	flags.StringVar(&fetch.SHA256, "sha256", "", "expected SHA-256 of the file behind --url (hex)")
	flags.StringVar(&fetch.Revision, "revision", "", "commit the source is pinned to (required with --url, recorded for local inputs when given)")
	flags.StringVar(&output, "output", "", "corpus file to write")
	flags.BoolVar(&allowAny, "allow-any-output", false, "allow --output outside a "+ScratchDir+" directory")
	flags.StringVar(&name, "name", "", "corpus name (default: the dataset name)")
	flags.StringVar(&lang, "lang", "", "language code of the texts (default en)")
	flags.IntVar(&limit, "limit", 0, "keep only the first N cases (0 keeps all)")
	flags.StringVar(&entities, "entities", "", "presidio: comma-separated entity types mapped to detect_pii (default "+strings.Join(DefaultPresidioEntities, ",")+")")
	flags.DurationVar(&timeout, "timeout", 2*time.Minute, "download timeout")
	switch err := flags.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return ExitOK
	case err != nil:
		return ExitUsage
	case flags.NArg() > 0:
		return usage(stderr, fmt.Errorf("unexpected argument %q", flags.Arg(0)))
	}

	kind, err := ParseDataset(dataset)
	if err != nil {
		return usage(stderr, err)
	}
	if err := CheckOutputPath(output, allowAny); err != nil {
		return usage(stderr, err)
	}
	if limit < 0 {
		return usage(stderr, errors.New("--limit must not be negative"))
	}
	if (fetch.URL == "") == (len(inputs) == 0) {
		return usage(stderr, errors.New("give either --input or --url"))
	}
	if fetch.URL != "" {
		if err := fetch.validate(); err != nil {
			return usage(stderr, err)
		}
	}
	if len(inputs) > 0 && (fetch.SHA256 != "" || (fetch.Revision != "" && !revisionPattern.MatchString(fetch.Revision))) {
		return usage(stderr, errors.New("--sha256 only applies to --url, and --revision must be a commit hash"))
	}

	opts := Options{Name: name, Limit: limit, Lang: lang}
	if entities != "" {
		if kind != Presidio {
			return usage(stderr, errors.New("--entities only applies to --dataset presidio"))
		}
		opts.Entities = strings.Split(entities, ",")
	}

	files, source, err := readInputs(ctx, kind, fetch, inputs, timeout)
	if err != nil {
		return failure(stderr, err)
	}
	opts.Source = source
	result, err := convert(kind, files, opts)
	if err != nil {
		return failure(stderr, err)
	}

	var encoded bytes.Buffer
	if err := result.Write(&encoded); err != nil {
		return failure(stderr, err)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return failure(stderr, fmt.Errorf("create output directory: %w", err))
	}
	if err := os.WriteFile(output, encoded.Bytes(), 0o644); err != nil {
		return failure(stderr, fmt.Errorf("write corpus: %w", err))
	}
	fmt.Fprintf(stdout, "wrote %d cases to %s (sha256 %s)\nskipped: %s\nThis corpus derives from public data: do not commit it.\n",
		len(result.Cases), output, SHA256Hex(encoded.Bytes()), describe(result.Skips))
	return ExitOK
}

func failure(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "eval-import: error: %v\n", err)
	return ExitFailure
}

func usage(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "eval-import: error: %v\n", err)
	return ExitUsage
}

// readInputs loads the dataset bytes from disk or from one pinned download and
// returns the provenance to record.
func readInputs(ctx context.Context, kind Dataset, fetch FetchRequest, inputs []string, timeout time.Duration) ([][]byte, eval.Source, error) {
	source := eval.Source{Revision: fetch.Revision}
	if fetch.URL != "" {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		data, err := Fetch(ctx, nil, fetch)
		if err != nil {
			return nil, source, err
		}
		source.URL, source.SHA256 = fetch.URL, fetch.SHA256
		return [][]byte{data}, source, nil
	}
	paths, err := expandInputs(kind, inputs)
	if err != nil {
		return nil, source, err
	}
	files := make([][]byte, 0, len(paths))
	for _, path := range paths {
		handle, err := os.Open(path)
		if err != nil {
			return nil, source, fmt.Errorf("open input: %w", err)
		}
		data, err := ReadLimited(handle)
		handle.Close()
		if err != nil {
			return nil, source, fmt.Errorf("%s: %w", path, err)
		}
		files = append(files, data)
	}
	if len(files) == 1 {
		source.SHA256 = SHA256Hex(files[0])
	}
	return files, source, nil
}

// expandInputs resolves --input paths. Only AgentDojo takes several files or
// directories; directories are walked recursively for *.json, in sorted order.
func expandInputs(kind Dataset, inputs []string) ([]string, error) {
	if kind != AgentDojo {
		if len(inputs) != 1 {
			return nil, fmt.Errorf("%s takes exactly one --input file", kind)
		}
		return inputs, nil
	}
	var paths []string
	for _, input := range inputs {
		info, err := os.Stat(input)
		if err != nil {
			return nil, fmt.Errorf("open input: %w", err)
		}
		if !info.IsDir() {
			paths = append(paths, input)
			continue
		}
		walkErr := filepath.WalkDir(input, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".json") {
				paths = append(paths, path)
			}
			return nil
		})
		if walkErr != nil {
			return nil, fmt.Errorf("walk %s: %w", input, walkErr)
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, errors.New("no *.json trace found in --input")
	}
	return paths, nil
}

func convert(kind Dataset, files [][]byte, opts Options) (*Result, error) {
	switch kind {
	case BIPIA:
		return ImportBIPIA(files[0], opts)
	case Presidio:
		return ImportPresidio(files[0], opts)
	}
	traces := make([]AgentDojoTrace, 0, len(files))
	for index, data := range files {
		trace, err := ParseAgentDojoTrace(data)
		if err != nil {
			return nil, fmt.Errorf("input %d: %w", index+1, err)
		}
		traces = append(traces, trace)
	}
	return ImportAgentDojo(traces, opts)
}
