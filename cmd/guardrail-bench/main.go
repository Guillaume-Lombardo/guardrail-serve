// Command guardrail-bench measures semantic prompt-injection candidates through
// the real guardrail-serve handler (ADR 0023). See README.md in this directory.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/g1lom/guardrail-serve/cmd/guardrail-bench/bench"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "guardrail-bench:", err)
		os.Exit(1)
	}
}

const usage = `usage: guardrail-bench <command> [flags]

commands:
  run         measure one configuration on one corpus (writes a run file)
  calibrate   freeze the protocol from calibration runs
  export      bundle text-free run files for the report
  report      compute results JSON and Markdown tables from a bundle
  jev-models  list System One models (read-only GET /v1/models)
  jev-probe   one budgeted judge call on a fixed text to check a model name`

func run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "run":
		return runCommand(ctx, args[1:], stdout)
	case "calibrate":
		return calibrateCommand(args[1:], stdout)
	case "export":
		return exportCommand(args[1:], stdout)
	case "report":
		return reportCommand(args[1:], stdout)
	case "jev-models":
		return modelsCommand(ctx, args[1:], stdout)
	case "jev-probe":
		return probeCommand(ctx, args[1:], stdout)
	}
	return fmt.Errorf("unknown command %q\n%s", args[0], usage)
}

func defaultCacheDir() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "guardrail-bench")
	}
	return ".agent-tmp/guardrail-bench-cache"
}

func runCommand(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	corpus := flags.String("corpus", "", "corpus: "+strings.Join(bench.CorpusNames(), ", "))
	mode := flags.String("mode", "", "rules, union, judge or cascade")
	model := flags.String("model", "", "registered model name (union, cascade)")
	sidecarURL := flags.String("sidecar-url", "", "live sidecar base URL; empty replays cached scores")
	sidecarImage := flags.String("sidecar-image", "", "sidecar image id, recorded in the run file")
	thresholdSource := flags.String("threshold", "frozen", "frozen (protocol) or current (0.9, cascade primary only); calibration runs ignore it")
	replayDelay := flags.Bool("replay-delay", false, "replay cached answers with their recorded upstream latency")
	jevLive := flags.Bool("jev-live", false, "allow paid System One calls through the budgeted proxy")
	jevKeyFile := flags.String("jev-key-file", "", "file holding the System One key (for example /dev/fd/3); never an argument")
	maxCalls := flags.Int("max-calls", bench.DefaultBudget.MaxCalls, "paid call cap")
	maxUSD := flags.Float64("max-usd", bench.DefaultBudget.MaxUSD, "cumulative paid cost cap in USD")
	cacheDir := flags.String("cache-dir", defaultCacheDir(), "private cache outside Git")
	protocolPath := flags.String("protocol", "", "frozen protocol (required except on the calibration split)")
	warmup := flags.Int("warmup", 3, "warmup requests before measuring (live sidecar only)")
	runID := flags.String("run-id", "", "run identifier")
	out := flags.String("out", "", "run file to write")
	logPath := flags.String("log", "", "service log file (default: discarded)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *out == "" || *runID == "" || *corpus == "" {
		return errors.New("run needs -corpus, -run-id and -out")
	}
	if *corpus != bench.CorpusCalibration && *protocolPath == "" {
		return errors.New("every corpus but the calibration split needs -protocol")
	}
	parsedMode, err := bench.ParseMode(*mode)
	if err != nil {
		return err
	}
	cfg := bench.RunConfig{
		Root: *root, Corpus: *corpus, Mode: parsedMode, Model: *model, SidecarURL: *sidecarURL, SidecarImage: *sidecarImage,
		ReplayDelay: *replayDelay, JevLive: *jevLive, CacheDir: *cacheDir, Warmup: *warmup, RunID: *runID,
		Budget: bench.Budget{MaxCalls: *maxCalls, MaxUSD: *maxUSD, StopAfter: bench.DefaultBudget.StopAfter},
	}
	if *protocolPath != "" {
		protocol, sha, err := loadProtocol(*protocolPath)
		if err != nil {
			return err
		}
		cfg.Protocol, cfg.ProtocolSHA = protocol, sha
		if *corpus != bench.CorpusCalibration {
			// Measuring after calibration needs the protocol frozen in Git.
			if cfg.ProtocolCommit, err = bench.CommittedFile(*protocolPath); err != nil {
				return err
			}
		}
	}
	if parsedMode == bench.ModeUnion || parsedMode == bench.ModeCascade {
		cfg.Threshold = bench.DefaultThreshold
		if *corpus != bench.CorpusCalibration {
			if cfg.Protocol == nil {
				return errors.New("this corpus needs -protocol")
			}
			switch *thresholdSource {
			case "frozen":
				frozen, err := cfg.Protocol.Model(*model)
				if err != nil {
					return err
				}
				cfg.Threshold = frozen.Threshold
			case "current":
				cfg.Threshold = cfg.Protocol.DefaultThreshold
			default:
				return errors.New("-threshold must be frozen or current")
			}
		}
		if parsedMode == bench.ModeCascade {
			zone := bench.Zone{Lower: cfg.Protocol.Zone.Lower, Upper: cfg.Protocol.Zone.Upper}
			cfg.Zone, cfg.Threshold = &zone, zone.Upper
		}
	}
	if *jevLive {
		if *jevKeyFile == "" {
			return errors.New("-jev-live needs -jev-key-file")
		}
		key, err := readKey(*jevKeyFile)
		if err != nil {
			return err
		}
		cfg.JevKey = key
	}
	if *logPath != "" {
		file, err := os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		cfg.LogOutput = file
	}
	result, err := bench.Run(ctx, cfg)
	if err != nil {
		return err
	}
	if err := bench.WriteJSON(*out, result); err != nil {
		return err
	}
	errorsCount := 0
	for _, item := range result.Cases {
		if item.Status != bench.StatusOK {
			errorsCount++
		}
	}
	fmt.Fprintf(stdout, "%s: %d cases, %d errors -> %s\n", result.RunID, len(result.Cases), errorsCount, *out)
	if result.Judge != nil {
		fmt.Fprintf(stdout, "judge proxy: %d requests, %d upstream, %d cache hits, %d refused, %d egress blocked, %d failures, %d input tokens, USD %.6f %s\n",
			result.Judge.Requests, result.Judge.Upstream, result.Judge.CacheHits, result.Judge.Refused, result.Judge.EgressBlocked,
			result.Judge.Failures, result.Judge.InputTokens, result.Judge.CostUSD, result.Judge.StopReason)
	}
	return nil
}

// readKey reads a key file without echoing it; errors never contain the value.
func readKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("key file cannot be opened")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 16<<10))
	if err != nil {
		return nil, errors.New("key file cannot be read")
	}
	key := []byte(strings.TrimSpace(string(data)))
	if len(key) == 0 || strings.ContainsAny(string(key), " \t\r\n") {
		return nil, errors.New("key file does not hold a single token")
	}
	return key, nil
}

func loadProtocol(path string) (*bench.Protocol, string, error) {
	var protocol bench.Protocol
	if err := bench.ReadJSON(path, &protocol); err != nil {
		return nil, "", err
	}
	if protocol.Format != bench.ProtocolFormat || protocol.Version != bench.FormatVersion {
		return nil, "", errors.New("not a guardrail-bench protocol")
	}
	sha, err := bench.FileSHA256(path)
	return &protocol, sha, err
}

func readRun(path string) (*bench.RunFile, string, error) {
	var run bench.RunFile
	if err := bench.ReadJSON(path, &run); err != nil {
		return nil, "", err
	}
	if run.Format != bench.RunFormat || run.Version != bench.FormatVersion {
		return nil, "", fmt.Errorf("%s is not a guardrail-bench run", path)
	}
	sha, err := bench.FileSHA256(path)
	return &run, sha, err
}

func calibrateCommand(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("calibrate", flag.ContinueOnError)
	rulesPath := flags.String("rules", "", "rules run on the calibration split")
	out := flags.String("out", "", "protocol file to write")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *rulesPath == "" || *out == "" || flags.NArg() == 0 {
		return errors.New("calibrate needs -rules, -out and one classifier run per model")
	}
	rules, sha, err := readRun(*rulesPath)
	if err != nil {
		return err
	}
	hashes := map[string]string{rules.RunID: sha}
	var models []*bench.RunFile
	for _, path := range flags.Args() {
		run, sha, err := readRun(path)
		if err != nil {
			return err
		}
		hashes[run.RunID] = sha
		models = append(models, run)
	}
	protocol, err := bench.Calibrate(rules, models, hashes)
	if err != nil {
		return err
	}
	if err := bench.WriteJSON(*out, protocol); err != nil {
		return err
	}
	protocolSHA, err := bench.FileSHA256(*out)
	if err != nil {
		return err
	}
	for _, model := range protocol.Models {
		fmt.Fprintf(stdout, "%-16s threshold %-10s (%s) union FP %d/%d TP %d/%d\n", model.Name, fmt.Sprint(model.Threshold), model.Rule,
			model.Calibration.FP, model.Calibration.FP+model.Calibration.TN, model.Calibration.TP, model.Calibration.TP+model.Calibration.FN)
	}
	fmt.Fprintf(stdout, "zone [%g, %g] with %d/%d calibration texts\nprotocol sha256 %s\n", protocol.Zone.Lower, protocol.Zone.Upper,
		protocol.Zone.TextsInZone, protocol.Positives+protocol.Negatives, protocolSHA)
	return nil
}

func exportCommand(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("export", flag.ContinueOnError)
	protocolPath := flags.String("protocol", "", "frozen protocol")
	out := flags.String("out", "", "bundle to write")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *protocolPath == "" || *out == "" || flags.NArg() == 0 {
		return errors.New("export needs -protocol, -out and run files")
	}
	_, sha, err := loadProtocol(*protocolPath)
	if err != nil {
		return err
	}
	if _, err := bench.CommittedFile(*protocolPath); err != nil {
		return err
	}
	bundle := bench.Bundle{Format: bench.BundleFormat, Version: bench.FormatVersion, ProtocolSHA256: sha}
	for _, path := range flags.Args() {
		run, _, err := readRun(path)
		if err != nil {
			return err
		}
		if run.Corpus != bench.CorpusCalibration && run.ProtocolSHA256 != sha {
			return fmt.Errorf("%s was measured under another protocol", path)
		}
		bundle.Runs = append(bundle.Runs, *run)
	}
	if err := bench.WriteJSON(*out, bundle); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%d runs -> %s\n", len(bundle.Runs), *out)
	return nil
}

func reportCommand(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	bundlePath := flags.String("bundle", "", "exported runs")
	protocolPath := flags.String("protocol", "", "frozen protocol")
	root := flags.String("root", ".", "repository root (canonical corpora)")
	out := flags.String("out", "", "results JSON to write")
	markdown := flags.String("markdown", "", "Markdown tables to write (optional)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" || *protocolPath == "" || *out == "" {
		return errors.New("report needs -bundle, -protocol and -out")
	}
	protocol, sha, err := loadProtocol(*protocolPath)
	if err != nil {
		return err
	}
	if _, err := bench.CommittedFile(*protocolPath); err != nil {
		return err
	}
	var bundle bench.Bundle
	if err := bench.ReadJSON(*bundlePath, &bundle); err != nil {
		return err
	}
	corpora := map[string]*bench.LoadedCorpus{}
	for _, name := range bench.CorpusNames() {
		corpus, err := bench.LoadCorpus(*root, name)
		if err != nil {
			return err
		}
		corpora[name] = corpus
	}
	results, err := bench.Report(&bundle, protocol, sha, corpora)
	if err != nil {
		return err
	}
	if err := bench.WriteJSON(*out, results); err != nil {
		return err
	}
	if *markdown != "" {
		if err := os.WriteFile(*markdown, []byte(bench.Markdown(results)), 0o644); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "%d rows, D1 passing: %v, change default: %v -> %s\n", len(results.Rows), results.Decision.Passing, results.Decision.ChangeDefault, *out)
	return nil
}

// modelsCommand lists System One models with a read-only, unbilled GET.
func modelsCommand(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("jev-models", flag.ContinueOnError)
	keyFile := flags.String("jev-key-file", "", "file holding the System One key (for example /dev/fd/3)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	key, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	models, err := bench.ListJevModels(ctx, &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 20 * time.Second}, bench.JevModelsURL, key)
	if err != nil {
		return err
	}
	for _, model := range models {
		fmt.Fprintf(stdout, "%s\t%s\t%s\n", model.Name, model.ReleaseDate, model.Description)
	}
	return nil
}

// probeCommand checks that a model name is served, with one capped, ledgered call.
func probeCommand(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("jev-probe", flag.ContinueOnError)
	keyFile := flags.String("jev-key-file", "", "file holding the System One key (for example /dev/fd/3)")
	model := flags.String("model", bench.JevFixed.Model, "model name to probe")
	cacheDir := flags.String("cache-dir", defaultCacheDir(), "private cache outside Git")
	if err := flags.Parse(args); err != nil {
		return err
	}
	key, err := readKey(*keyFile)
	if err != nil {
		return err
	}
	cache, err := bench.NewCache(filepath.Join(*cacheDir, "jev-probe"))
	if err != nil {
		return err
	}
	ledger, err := bench.OpenLedger(filepath.Join(*cacheDir, "jev-ledger.jsonl"))
	if err != nil {
		return err
	}
	defer ledger.Close()
	result, err := bench.ProbeJev(ctx, bench.JevProxyConfig{Key: key, Cache: cache, Ledger: ledger}, *model)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "requested %s: status %d, served model %q, %d input tokens, USD %.8f\n",
		*model, result.Status, result.ServedModel, result.InputTokens, result.CostUSD)
	return nil
}
