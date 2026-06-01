package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"

	"runtime/debug"

	"github.com/hobeone/par2engine/par2"
)

// stringSliceFlag is a flag.Value that accumulates repeated -flag values.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string { return strings.Join(*s, ", ") }
func (s *stringSliceFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// Exit codes matching par2cmdline standard specifications
const (
	ExitSuccess                     = 0
	ExitRepairPossible              = 1 // verification failed but repair is possible
	ExitRepairNotPossible           = 2 // verification failed and not enough parity, or repair failed
	ExitInvalidCommandLineArguments = 3 // bad flags or arguments
	ExitLogicError                  = 4 // unexpected runtime crash or logic issue
)

func main() {
	os.Exit(runCLI())
}

func runCLI() int {
	name := filepath.Base(os.Args[0])

	flagSet := flag.NewFlagSet(name, flag.ContinueOnError)

	var (
		numThreads    int
		memMB         int64
		cpuProfile    string
		memProfile    string
		maxFileSizeMB int64
		verbose       bool
		versionFlag   bool
		candidates    stringSliceFlag
	)

	flagSet.IntVar(&numThreads, "t", runtime.NumCPU(), "number of concurrent processing threads")
	flagSet.Int64Var(&memMB, "m", 16, "memory limit in megabytes for data buffers")
	flagSet.StringVar(&cpuProfile, "cpuprofile", "", "write CPU profile to file")
	flagSet.StringVar(&memProfile, "memprofile", "", "write memory profile to file")
	flagSet.Int64Var(&maxFileSizeMB, "max-file-size", 100, "maximum PAR2 index file size in megabytes")
	flagSet.BoolVar(&verbose, "v", false, "enable verbose structured slog logging")
	flagSet.BoolVar(&versionFlag, "version", false, "print version information")
	flagSet.Var(&candidates, "candidate", "extra file to scan as a shard source even if its name does not match\n\t(repeat for multiple files; path is relative to the PAR2 directory)")

	// Parse flags
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		return ExitInvalidCommandLineArguments
	}

	if versionFlag {
		v := "unknown"
		if info, ok := debug.ReadBuildInfo(); ok {
			v = info.Main.Version
		}
		fmt.Printf("%s version %s\n", name, v)
		return ExitSuccess
	}

	args := flagSet.Args()
	if len(args) < 2 {
		printUsage(name, flagSet)
		return ExitInvalidCommandLineArguments
	}

	cmd := strings.ToLower(args[0])
	par2Path := args[1]

	// Validate subcommand
	if cmd != "v" && cmd != "verify" && cmd != "r" && cmd != "repair" {
		fmt.Fprintf(os.Stderr, "Error: unknown command %q (choose 'verify' or 'repair')\n", cmd)
		printUsage(name, flagSet)
		return ExitInvalidCommandLineArguments
	}

	// Profile setup
	cleanup, err := setupProfiling(cpuProfile, memProfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitLogicError
	}
	if cleanup != nil {
		defer cleanup()
	}

	// Setup Logger
	logLevel := slog.LevelInfo
	if verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	// Setup graceful cancellation on interrupt signal
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Initialize Decoder
	memLimitBytes := memMB * 1024 * 1024
	maxFileLimitBytes := maxFileSizeMB * 1024 * 1024
	// Allow packets to be up to 1.25x the file limit, or at least the default 128MB
	maxPacketLimitBytes := max(maxFileLimitBytes*5/4, 128*1024*1024)

	d, err := par2.NewDecoder(ctx, par2Path, par2.DecoderOptions{
		NumGoroutines: numThreads,
		MemoryLimit:   memLimitBytes,
		MaxFileSize:   maxFileLimitBytes,
		MaxPacketSize: maxPacketLimitBytes,
		Logger:        logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing PAR2 decoder: %v\n", err)
		return ExitInvalidCommandLineArguments
	}
	defer func() { _ = d.Close() }()

	if err := expandCandidates(d, par2Path, candidates, logger); err != nil {
		fmt.Fprintf(os.Stderr, "Error processing candidate files: %v\n", err)
		return ExitInvalidCommandLineArguments
	}

	// 1. Perform file integrity scans
	verifyProgressChan := make(chan par2.Progress, 100)
	done := newProgressReporter("Verifying", verbose, logger, verifyProgressChan)

	err = d.VerifyScans(ctx, verifyProgressChan)
	close(verifyProgressChan)
	<-done
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError during verification scanning: %v\n", err)
		return ExitLogicError
	}

	counts := d.ShardCounts()

	logger.Info("Verification scanning complete",
		"usableDataBlocks", counts.UsableDataShardCount,
		"unusableDataBlocks", counts.UnusableDataShardCount,
		"usableParityBlocks", counts.UsableParityShardCount)

	// Dispatch subcommand
	switch cmd {
	case "v", "verify":
		return handleVerifyCommand(logger, counts)
	case "r", "repair":
		return handleRepairCommand(ctx, d, logger, counts, verbose)
	default:
		logger.Error("Unknown command", "command", cmd)
		printUsage(name, flagSet)
		return ExitInvalidCommandLineArguments
	}
}

// setupProfiling configures CPU and Memory profiling if requested, returning a cleanup closure.
func setupProfiling(cpuProfile, memProfile string) (cleanup func(), err error) {
	var cpuFile *os.File
	if cpuProfile != "" {
		cpuFile, err = os.Create(cpuProfile)
		if err != nil {
			return nil, fmt.Errorf("failed to create CPU profile file: %w", err)
		}
		if err = pprof.StartCPUProfile(cpuFile); err != nil {
			_ = cpuFile.Close()
			return nil, fmt.Errorf("failed to start CPU profiling: %w", err)
		}
	}

	cleanup = func() {
		if cpuFile != nil {
			pprof.StopCPUProfile()
			_ = cpuFile.Close()
		}
		if memProfile != "" {
			f, err := os.Create(memProfile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to create memory profile file: %v\n", err)
				return
			}
			defer func() { _ = f.Close() }()
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to write memory profile: %v\n", err)
			}
		}
	}

	return cleanup, nil
}

// newProgressReporter starts a background reporter goroutine printing throttled label percentages.
func newProgressReporter(label string, verbose bool, logger *slog.Logger, ch <-chan par2.Progress) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		for p := range ch {
			if verbose {
				logger.Debug(label+" progress", "percent", fmt.Sprintf("%.2f%%", p.Percent))
			} else {
				fmt.Printf("\r%s... %.1f%%", label, p.Percent)
				_ = os.Stdout.Sync()
			}
		}
		if !verbose {
			fmt.Println()
		}
		close(done)
	}()
	return done
}

// expandCandidates resolves candidate glob strings and registers the files as engine input source candidates.
func expandCandidates(d *par2.Decoder, par2Path string, candidates []string, logger *slog.Logger) error {
	par2Dir := filepath.Dir(par2Path)
	for _, c := range candidates {
		if !strings.ContainsAny(c, "*?[") {
			if err := d.AddCandidateFile(c); err != nil {
				return fmt.Errorf("error adding candidate file %q: %w", c, err)
			}
			continue
		}
		matches, err := filepath.Glob(filepath.Join(par2Dir, c))
		if err != nil {
			return fmt.Errorf("invalid glob pattern %q: %w", c, err)
		}
		if len(matches) == 0 {
			logger.Warn("No files matched glob pattern", "pattern", c)
			continue
		}
		for _, match := range matches {
			rel, err := filepath.Rel(par2Dir, match)
			if err != nil {
				return fmt.Errorf("error resolving path %q: %w", match, err)
			}
			if err := d.AddCandidateFile(rel); err != nil {
				return fmt.Errorf("error adding candidate file %q: %w", rel, err)
			}
		}
	}
	return nil
}

// handleVerifyCommand evaluates shard integrity counts and returns the correct verify CLI exit code.
func handleVerifyCommand(logger *slog.Logger, counts par2.ShardCounts) int {
	if !counts.RepairNeeded() {
		logger.Info("All protected files are healthy and verified.")
		return ExitSuccess
	}
	if counts.RepairPossible() {
		logger.Warn("Repair is REQUIRED and POSSIBLE.",
			"missingBlocks", counts.UnusableDataShardCount,
			"availableParity", counts.UsableParityShardCount,
			"filesToRename", counts.RenamesNeeded)
		return ExitRepairPossible
	}
	logger.Error("Repair is REQUIRED but NOT possible.",
		"missingBlocks", counts.UnusableDataShardCount,
		"availableParity", counts.UsableParityShardCount)
	return ExitRepairNotPossible
}

// handleRepairCommand triggers decoder repair and returns the correct repair CLI exit code.
func handleRepairCommand(ctx context.Context, d *par2.Decoder, logger *slog.Logger, counts par2.ShardCounts, verbose bool) int {
	if !counts.RepairNeeded() {
		logger.Info("No repair needed. All files are healthy.")
		return ExitSuccess
	}

	if !counts.RepairPossible() {
		logger.Error("Repair not possible.",
			"missingBlocks", counts.UnusableDataShardCount,
			"availableParity", counts.UsableParityShardCount)
		return ExitRepairNotPossible
	}

	repairProgressChan := make(chan par2.Progress, 100)
	done := newProgressReporter("Repairing", verbose, logger, repairProgressChan)

	err := d.Repair(ctx, repairProgressChan)
	close(repairProgressChan)
	<-done

	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError during repair operation: %v\n", err)
		return ExitRepairNotPossible
	}

	logger.Info("Repair operation completed successfully! All files verified.")
	return ExitSuccess
}

func printUsage(name string, fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, "PAR2 Engine - High-performance verification and repair\n")
	fmt.Fprintf(os.Stderr, "\nUsage:\n")
	fmt.Fprintf(os.Stderr, "  %s [options] verify <set.par2> : Verify the integrity of the files\n", name)
	fmt.Fprintf(os.Stderr, "  %s [options] repair <set.par2> : Repair corrupt/missing files\n", name)
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	fs.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n")
}
