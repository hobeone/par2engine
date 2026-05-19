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
)

// Exit codes matching par2cmdline standard specifications
const (
	ExitSuccess                      = 0
	ExitRepairPossible               = 1 // verification failed but repair is possible
	ExitRepairNotPossible            = 2 // verification failed and not enough parity, or repair failed
	ExitInvalidCommandLineArguments  = 3 // bad flags or arguments
	ExitLogicError                   = 4 // unexpected runtime crash or logic issue
)

func main() {
	os.Exit(runCLI())
}

func runCLI() int {
	name := filepath.Base(os.Args[0])

	flagSet := flag.NewFlagSet(name, flag.ContinueOnError)
	
	var (
		numThreads int
		memMB      int64
		cpuProfile string
		memProfile string
		maxFileSizeMB int64
		verbose       bool
	)

	flagSet.IntVar(&numThreads, "t", runtime.NumCPU(), "number of concurrent processing threads")
	flagSet.Int64Var(&memMB, "m", 16, "memory limit in megabytes for data buffers")
	flagSet.StringVar(&cpuProfile, "cpuprofile", "", "write CPU profile to file")
	flagSet.StringVar(&memProfile, "memprofile", "", "write memory profile to file")
	flagSet.Int64Var(&maxFileSizeMB, "max-file-size", 100, "maximum PAR2 index file size in megabytes")
	flagSet.BoolVar(&verbose, "v", false, "enable verbose structured slog logging")

	// Parse flags
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		return ExitInvalidCommandLineArguments
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		logger.Warn("Interrupt signal received. Shutting down gracefully...")
		cancel()
	}()

	// Initialize Decoder
	memLimitBytes := memMB * 1024 * 1024
	maxFileLimitBytes := maxFileSizeMB * 1024 * 1024
	// Allow packets to be up to 1.25x the file limit, or at least the default 128MB
	maxPacketLimitBytes := maxFileLimitBytes * 5 / 4
	if maxPacketLimitBytes < 128*1024*1024 {
		maxPacketLimitBytes = 128 * 1024 * 1024
	}

	d, err := par2.NewDecoder(ctx, par2Path, numThreads, memLimitBytes, maxFileLimitBytes, maxPacketLimitBytes, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing PAR2 decoder: %v\n", err)
		return ExitInvalidCommandLineArguments
	}
	defer d.Close()

	// 1. Perform file integrity scans
	progressChan := make(chan par2.Progress, 100)
	go func() {
		for p := range progressChan {
			if verbose {
				logger.Debug("Progress update", "phase", p.Phase, "percent", fmt.Sprintf("%.2f%%", p.Percent))
			} else {
				fmt.Printf("\rProgress: %s... %.1f%%", p.Phase, p.Percent)
				_ = os.Stdout.Sync()
			}
		}
		if !verbose {
			fmt.Println()
		}
	}()

	err = d.VerifyScans(ctx, progressChan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError during verification scanning: %v\n", err)
		return ExitLogicError
	}

	counts := d.ShardCounts()
	close(progressChan)

	logger.Info("Verification scanning complete",
		"usableDataBlocks", counts.UsableDataShardCount,
		"unusableDataBlocks", counts.UnusableDataShardCount,
		"usableParityBlocks", counts.UsableParityShardCount)

	// If subcommand is verify
	if cmd == "v" || cmd == "verify" {
		if !counts.RepairNeeded() {
			logger.Info("All protected files are healthy and verified.")
			return ExitSuccess
		}
		if counts.RepairPossible() {
			logger.Warn("Repair is REQUIRED and POSSIBLE.", "missingBlocks", counts.UnusableDataShardCount, "availableParity", counts.UsableParityShardCount)
			return ExitRepairPossible
		}
		logger.Error("Repair is REQUIRED but NOT possible.", "missingBlocks", counts.UnusableDataShardCount, "availableParity", counts.UsableParityShardCount)
		return ExitRepairNotPossible
	}

	// If subcommand is repair
	if cmd == "r" || cmd == "repair" {
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
	}

	return ExitLogicError
}

func printUsage(name string, fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, "\nUsage:\n")
	fmt.Fprintf(os.Stderr, "  %s [options] verify <set.par2> : Verify the integrity of the files\n", name)
	fmt.Fprintf(os.Stderr, "  %s [options] repair <set.par2> : Repair corrupt/missing files\n", name)
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	fs.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\n")
}
