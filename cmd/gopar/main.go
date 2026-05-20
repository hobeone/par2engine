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

	"github.com/hobeone/par2engine/par2"
	"runtime/debug"
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

	// CPU Profiling setup
	if cpuProfile != "" {
		f, err := os.Create(cpuProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to create CPU profile file: %v\n", err)
			return ExitLogicError
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to start CPU profiling: %v\n", err)
			return ExitLogicError
		}
		defer pprof.StopCPUProfile()
	}

	// Memory Profiling setup
	if memProfile != "" {
		defer func() {
			f, err := os.Create(memProfile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to create memory profile file: %v\n", err)
				return
			}
			defer f.Close()
			runtime.GC() // get up-to-date statistics
			if err := pprof.WriteHeapProfile(f); err != nil {
				fmt.Fprintf(os.Stderr, "Error: failed to write memory profile: %v\n", err)
			}
		}()
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
	defer d.Close()

	par2Dir := filepath.Dir(par2Path)
	for _, c := range candidates {
		if !strings.ContainsAny(c, "*?[") {
			if err := d.AddCandidateFile(c); err != nil {
				fmt.Fprintf(os.Stderr, "Error adding candidate file %q: %v\n", c, err)
				return ExitInvalidCommandLineArguments
			}
			continue
		}
		matches, err := filepath.Glob(filepath.Join(par2Dir, c))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid glob pattern %q: %v\n", c, err)
			return ExitInvalidCommandLineArguments
		}
		if len(matches) == 0 {
			logger.Warn("No files matched glob pattern", "pattern", c)
			continue
		}
		for _, match := range matches {
			rel, err := filepath.Rel(par2Dir, match)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving path %q: %v\n", match, err)
				return ExitInvalidCommandLineArguments
			}
			if err := d.AddCandidateFile(rel); err != nil {
				fmt.Fprintf(os.Stderr, "Error adding candidate file %q: %v\n", rel, err)
				return ExitInvalidCommandLineArguments
			}
		}
	}

	// 1. Perform file integrity scans
	err = d.VerifyScans(ctx)
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
		if !counts.RepairNeeded() {
			logger.Info("All protected files are healthy and verified.")
			return ExitSuccess
		}
		if counts.RepairPossible() {
			logger.Warn("Repair is REQUIRED and POSSIBLE.", "missingBlocks", counts.UnusableDataShardCount, "availableParity", counts.UsableParityShardCount, "filesToRename", counts.RenamesNeeded)
			return ExitRepairPossible
		}
		logger.Error("Repair is REQUIRED but NOT possible.", "missingBlocks", counts.UnusableDataShardCount, "availableParity", counts.UsableParityShardCount)
		return ExitRepairNotPossible

	case "r", "repair":
		if !counts.RepairNeeded() {
			logger.Info("No repair needed. All files are healthy.")
			return ExitSuccess
		}

		if !counts.RepairPossible() {
			logger.Error("Repair not possible.", "missingBlocks", counts.UnusableDataShardCount, "availableParity", counts.UsableParityShardCount)
			return ExitRepairNotPossible
		}

		// Perform Repair
		repairProgressChan := make(chan par2.Progress, 100)
		go func() {
			for p := range repairProgressChan {
				if verbose {
					logger.Debug("Repair progress", "percent", fmt.Sprintf("%.2f%%", p.Percent))
				} else {
					fmt.Printf("\rRepairing... %.1f%%", p.Percent)
					_ = os.Stdout.Sync()
				}
			}
			if !verbose {
				fmt.Println()
			}
		}()

		err = d.Repair(ctx, repairProgressChan)
		close(repairProgressChan)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nError during repair operation: %v\n", err)
			return ExitRepairNotPossible
		}

		logger.Info("Repair operation completed successfully! All files verified.")
		return ExitSuccess

	default:
		logger.Error("Unknown command", "command", cmd)
		printUsage(name, flagSet)
		return ExitInvalidCommandLineArguments
	}

	return ExitLogicError
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
