package eval

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Exit codes. They are part of the CLI contract.
const (
	// ExitOK: the run completed and every request succeeded (or the corpus is valid).
	ExitOK = 0
	// ExitFailure: an unexpected local failure, such as an unwritable output file.
	ExitFailure = 1
	// ExitUsage: invalid flags, configuration or corpus. No request was sent.
	ExitUsage = 2
	// ExitRequestErrors: every case was attempted but some requests failed.
	// The report is written and its counts exclude the failed requests.
	ExitRequestErrors = 3
	// ExitAborted: the run stopped early; the report is partial.
	ExitAborted = 4
)

// Environment variables read by the command. The API key has no flag so that
// it never appears in a process list or shell history.
const (
	EnvBaseURL = "GUARDRAIL_EVAL_BASE_URL"
	EnvAPIKey  = "GUARDRAIL_EVAL_API_KEY"

	maxKeyFileBytes = 4096
)

const usageText = `Usage:
  guardrail-eval run      --corpus FILE [--corpus FILE...] --base-url URL [options]
  guardrail-eval validate --corpus FILE [--corpus FILE...]

Run evaluates labelled corpora against a running guardrail-serve through its
documented HTTP API and reports TP/FP/TN/FN, precision, recall and false
positive rate per detector. Validate checks corpus files offline.

Run "guardrail-eval run -h" for the options.
`

// Main runs the command and returns the process exit code.
func Main(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return ExitUsage
	}
	switch args[0] {
	case "run":
		return runCommand(ctx, args[1:], getenv, stdout, stderr)
	case "validate":
		return validateCommand(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return ExitOK
	}
	fmt.Fprintf(stderr, "guardrail-eval: unknown command %q\n\n%s", args[0], usageText)
	return ExitUsage
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func usageError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "guardrail-eval: error: %v\n", err)
	return ExitUsage
}

func loadCorpora(paths []string) ([]*Corpus, error) {
	if len(paths) == 0 {
		return nil, errors.New("at least one --corpus is required")
	}
	corpora := make([]*Corpus, 0, len(paths))
	names := map[string]string{}
	for _, path := range paths {
		corpus, err := LoadCorpus(path)
		if err != nil {
			return nil, err
		}
		if previous, dup := names[corpus.Header.Name]; dup {
			return nil, fmt.Errorf("corpus name %q is used by both %s and %s", corpus.Header.Name, previous, path)
		}
		names[corpus.Header.Name] = path
		corpora = append(corpora, corpus)
	}
	return corpora, nil
}

func validateCommand(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var corpusPaths stringList
	flags.Var(&corpusPaths, "corpus", "corpus file (repeatable)")
	if code, done := parseFlags(flags, args, stderr); done {
		return code
	}
	corpora, err := loadCorpora(corpusPaths)
	if err != nil {
		return usageError(stderr, err)
	}
	for _, corpus := range corpora {
		langs := map[string]bool{}
		for _, item := range corpus.Cases {
			langs[item.Lang] = true
		}
		fmt.Fprintf(stdout, "%s: %d cases, detectors [%s], languages [%s], sha256 %s\n", corpus.Header.Name, len(corpus.Cases),
			strings.Join(corpus.Detectors(), " "), strings.Join(sortedKeys(langs), " "), corpus.SHA256)
	}
	return ExitOK
}

// parseFlags returns done=true when the command must exit with code.
func parseFlags(flags *flag.FlagSet, args []string, stderr io.Writer) (code int, done bool) {
	switch err := flags.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		return ExitOK, true
	case err != nil:
		return ExitUsage, true
	case flags.NArg() > 0:
		fmt.Fprintf(stderr, "guardrail-eval: error: unexpected argument %q\n", flags.Arg(0))
		return ExitUsage, true
	}
	return 0, false
}

type runOptions struct {
	corpusPaths      stringList
	baseURL          string
	mode             string
	policy           string
	format           string
	output           string
	timeout          time.Duration
	runTimeout       time.Duration
	maxResponseBytes int64
	maxConsecutive   int
	apiKeyFile       string
	authScheme       string
	insecureAuth     bool
}

func runCommand(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var opts runOptions
	flags.Var(&opts.corpusPaths, "corpus", "corpus file (repeatable, required)")
	flags.StringVar(&opts.baseURL, "base-url", getenv(EnvBaseURL), "service base URL, including any API prefix (env "+EnvBaseURL+")")
	flags.StringVar(&opts.mode, "mode", string(ModeAnnotate), "annotate: policy findings via /v1/guardrails/{policy}; enforce: decisions via /scan/*")
	flags.StringVar(&opts.policy, "policy", "audit", "policy to evaluate in annotate mode")
	flags.StringVar(&opts.format, "format", string(FormatText), "report format: text or json")
	flags.StringVar(&opts.output, "output", "", "write the report to this file instead of stdout")
	flags.DurationVar(&opts.timeout, "timeout", DefaultTimeout, "per-request timeout")
	flags.DurationVar(&opts.runTimeout, "run-timeout", 0, "overall run timeout (0 disables)")
	flags.Int64Var(&opts.maxResponseBytes, "max-response-bytes", DefaultMaxResponseBytes, "maximum response body size")
	flags.IntVar(&opts.maxConsecutive, "max-consecutive-errors", DefaultMaxConsecutiveErrors, "abort after this many consecutive request errors (0 disables)")
	flags.StringVar(&opts.apiKeyFile, "api-key-file", "", "file containing the API key (alternative to env "+EnvAPIKey+")")
	flags.StringVar(&opts.authScheme, "auth-scheme", string(AuthBearer), "API key header: bearer (Authorization) or x-api-key")
	flags.BoolVar(&opts.insecureAuth, "allow-insecure-auth", false, "allow sending the API key over plain http to a non-loopback host")
	if code, done := parseFlags(flags, args, stderr); done {
		return code
	}
	policyExplicit := false
	flags.Visit(func(f *flag.Flag) { policyExplicit = policyExplicit || f.Name == "policy" })

	mode, err := ParseMode(opts.mode)
	if err != nil {
		return usageError(stderr, err)
	}
	if mode == ModeEnforce && policyExplicit {
		return usageError(stderr, errors.New("--policy only applies to --mode annotate"))
	}
	format, err := ParseFormat(opts.format)
	if err != nil {
		return usageError(stderr, err)
	}
	if opts.baseURL == "" {
		return usageError(stderr, fmt.Errorf("--base-url (or %s) is required", EnvBaseURL))
	}
	if opts.runTimeout < 0 {
		return usageError(stderr, errors.New("--run-timeout must not be negative"))
	}
	corpora, err := loadCorpora(opts.corpusPaths)
	if err != nil {
		return usageError(stderr, err)
	}
	apiKey, err := loadAPIKey(opts.apiKeyFile, getenv(EnvAPIKey))
	if err != nil {
		return usageError(stderr, err)
	}
	client, err := NewClient(ClientConfig{
		BaseURL: opts.baseURL, APIKey: apiKey, AuthScheme: AuthScheme(opts.authScheme), AllowInsecureAuth: opts.insecureAuth,
		Timeout: opts.timeout, MaxResponseBytes: opts.maxResponseBytes,
	})
	if err != nil {
		return usageError(stderr, err)
	}
	cfg := RunConfig{Mode: mode, Policy: opts.policy, MaxConsecutiveErrors: opts.maxConsecutive}
	if err := cfg.Validate(corpora); err != nil {
		return usageError(stderr, err)
	}

	if opts.runTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.runTimeout)
		defer cancel()
	}
	result, err := Run(ctx, client, cfg, corpora)
	if err != nil {
		fmt.Fprintf(stderr, "guardrail-eval: error: %v\n", err)
		return ExitFailure
	}
	target := Target{BaseURL: client.BaseURL(), Mode: mode}
	if mode == ModeAnnotate {
		target.Policy = opts.policy
	}
	report := BuildReport(result, target, corpora)

	var rendered bytes.Buffer
	if format == FormatJSON {
		err = report.WriteJSON(&rendered)
	} else {
		err = report.WriteText(&rendered)
	}
	if err == nil {
		err = writeReport(opts.output, rendered.Bytes(), stdout)
	}
	if err != nil {
		fmt.Fprintf(stderr, "guardrail-eval: error: write report: %v\n", err)
		return ExitFailure
	}

	switch result.Status {
	case StatusAborted:
		fmt.Fprintf(stderr, "guardrail-eval: aborted: %s; the report is partial\n", result.AbortReason)
		return ExitAborted
	case StatusCompleteWithErrors:
		fmt.Fprintf(stderr, "guardrail-eval: %d request errors; they are excluded from the counts\n", len(result.Failures))
		return ExitRequestErrors
	}
	return ExitOK
}

func writeReport(path string, data []byte, stdout io.Writer) error {
	if path == "" {
		_, err := stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// loadAPIKey returns the optional API key from a file or the environment.
// Giving both is rejected so the effective credential is never ambiguous.
func loadAPIKey(file, fromEnv string) (string, error) {
	fromEnv = strings.TrimSpace(fromEnv)
	if file == "" {
		return fromEnv, nil
	}
	if fromEnv != "" {
		return "", fmt.Errorf("both --api-key-file and %s are set; use only one", EnvAPIKey)
	}
	handle, err := os.Open(file)
	if err != nil {
		return "", errors.New("cannot open the API key file")
	}
	defer handle.Close()
	data, err := io.ReadAll(io.LimitReader(handle, maxKeyFileBytes+1))
	if err != nil || len(data) > maxKeyFileBytes {
		return "", errors.New("cannot read the API key file or it exceeds 4096 bytes")
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", errors.New("the API key file is empty")
	}
	return key, nil
}
