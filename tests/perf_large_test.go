//go:build perf

package tests

/*
HOWTO Pre-Generate the Golden Dataset:

1. Compile the genperf helper tool:
   go build -o genperf ./cmd/genperf

2. Run it to create the 18GB unique block dataset:
   ./genperf ~/software/par2_perf_data

3. Generate the canonical PAR2 set (BlockSize=4MB, ParityBlockCount=230) using C++ par2:
   cd ~/software/par2_perf_data
   par2 c -s4194304 -c230 set.par2 large-file.dat small-*.dat

---
HOWTO Run Verification-Only Profiling:

   export PAR2_PERF_DIR=/home/hobe/software/par2_perf_data
   export PAR2_PERF_WORKSPACE=/home/hobe/software/par2_perf_scratch
   go build -o par2engine-cli ./cmd/gopar
   go test -tags=perf -v ./tests/... -run=TestPerfLarge -args -perf.verify_only=true -perf.cpuprofile=cpu_verify.prof

---
HOWTO Run Full Repair Profiling:

   export PAR2_PERF_DIR=/home/hobe/software/par2_perf_data
   export PAR2_PERF_WORKSPACE=/home/hobe/software/par2_perf_scratch
   
   go build -o par2engine-cli ./cmd/gopar
   go test -tags=perf -v ./tests/... -run=TestPerfLarge -args -perf.cpuprofile=cpu_repair.prof
*/

import (
	"bytes"
	"crypto/md5"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var cpuprofile = flag.String("perf.cpuprofile", "", "write cpu profile to file")
var memprofile = flag.String("perf.memprofile", "", "write mem profile to file")
var verifyOnly = flag.Bool("perf.verify_only", false, "only run the verification scan phase and profile it")

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func TestPerfLarge(t *testing.T) {
	perfDir := os.Getenv("PAR2_PERF_DIR")
	if perfDir == "" {
		t.Skip("PAR2_PERF_DIR environment variable is not set. Skipping E2E 18GB performance test.\n" +
			"To run this test, pre-generate the dataset inside a folder (see instructions in comments) " +
			"and run:\n" +
			"  export PAR2_PERF_DIR=/path/to/folder && go test -tags=perf -v ./tests/... -run=TestPerfLarge")
	}

	// Check that the golden dataset exists in perfDir
	largeFilePathSrc := filepath.Join(perfDir, "large-file.dat")
	if _, err := os.Stat(largeFilePathSrc); err != nil {
		t.Fatalf("Golden large-file.dat not found in PAR2_PERF_DIR (%s): %v", perfDir, err)
	}
	par2PathSrc := filepath.Join(perfDir, "set.par2")
	if _, err := os.Stat(par2PathSrc); err != nil {
		t.Fatalf("Golden set.par2 index not found in PAR2_PERF_DIR (%s): %v", perfDir, err)
	}

	// Create workspace directory: either user-specified scratch disk or fallback automated TempDir
	workspaceDir := os.Getenv("PAR2_PERF_WORKSPACE")
	var dir string
	var keepWorkspace bool
	if workspaceDir != "" {
		// Ensure it exists
		if err := os.MkdirAll(workspaceDir, 0755); err != nil {
			t.Fatalf("failed to create custom workspace parent directory: %v", err)
		}
		dir = filepath.Join(workspaceDir, fmt.Sprintf("par2-perf-run-%d", time.Now().Unix()))
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create custom workspace run directory: %v", err)
		}
		keepWorkspace = true
		t.Logf("Performance test workspace initialized at CUSTOM location (will NOT be automatically deleted): %s", dir)
	} else {
		dir = t.TempDir()
		t.Logf("Performance test workspace initialized at standard TempDir (will be automatically deleted): %s", dir)
	}

	if !keepWorkspace {
		defer os.RemoveAll(dir)
	}

	// Resolve and load all small files, large file, and PAR2 volume files from perfDir
	entries, err := os.ReadDir(perfDir)
	if err != nil {
		t.Fatalf("failed to read PAR2_PERF_DIR: %v", err)
	}

	t.Log("Copying golden dataset to temporary workspace...")
	startCopy := time.Now()
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".dat") || strings.HasSuffix(name, ".par2") {
			src := filepath.Join(perfDir, name)
			dest := filepath.Join(dir, name)
			if err := copyFile(src, dest); err != nil {
				t.Fatalf("failed to copy %s: %v", name, err)
			}
		}
	}
	t.Logf("Successfully copied golden dataset in %s", time.Since(startCopy))

	largeFilePath := filepath.Join(dir, "large-file.dat")
	par2Path := filepath.Join(dir, "set.par2")

	// 1. Save small files originals and compute pre-corruption hashes of the golden files
	t.Log("Computing pre-corruption reference MD5 hashes from workspace copies...")
	computeMD5 := func(path string) [16]byte {
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("failed to open file for md5: %v", err)
		}
		defer f.Close()
		hasher := md5.New()
		_, _ = io.Copy(hasher, f)
		var h [16]byte
		copy(h[:], hasher.Sum(nil))
		return h
	}

	origLargeHash := computeMD5(largeFilePath)

	smallOriginals := make(map[string][]byte)
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("small-%d.dat", i)
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("failed to read golden small file %s: %v", name, err)
		}
		smallOriginals[name] = data
	}

	// 2. Corrupt files just like Usenet packages:
	t.Log("Simulating package corruptions...")
	// Delete small-3.dat and small-7.dat
	if err := os.Remove(filepath.Join(dir, "small-3.dat")); err != nil {
		t.Fatalf("failed to delete small-3: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "small-7.dat")); err != nil {
		t.Fatalf("failed to delete small-7: %v", err)
	}

	// Flip bytes in large-file.dat at 4 separate block offsets (offsets: 100MB, 5GB, 10GB, 15GB)
	offsets := []int64{
		100 * 1024 * 1024,
		5 * 1024 * 1024 * 1024,
		10 * 1024 * 1024 * 1024,
		15 * 1024 * 1024 * 1024,
	}
	fLarge, err := os.OpenFile(largeFilePath, os.O_RDWR, 0644)
	if err != nil {
		t.Fatalf("failed to open large file for corruption: %v", err)
	}
	for _, off := range offsets {
		b := make([]byte, 1)
		_, _ = fLarge.ReadAt(b, off)
		b[0] ^= 0xFF
		_, _ = fLarge.WriteAt(b, off)
	}
	fLarge.Close()
	t.Log("Corruptions successfully applied (2 small files deleted, 4 large blocks corrupted).")

	// Resolve absolute path to our par2engine-cli binary
	cliPath, err := filepath.Abs("../par2engine-cli")
	if err != nil {
		t.Fatalf("failed to resolve CLI binary path: %v", err)
	}

	// 3. Execute verify command using par2engine-cli (Forward profiles if verifyOnly is true)
	t.Log("Executing par2engine-cli verify...")
	var verifyArgs []string
	if *verifyOnly {
		if *cpuprofile != "" {
			absCPU := resolveProfilePath(*cpuprofile)
			verifyArgs = append(verifyArgs, "-cpuprofile", absCPU)
		}
		if *memprofile != "" {
			absMem := resolveProfilePath(*memprofile)
			verifyArgs = append(verifyArgs, "-memprofile", absMem)
		}
	}
	verifyArgs = append(verifyArgs, "verify", par2Path)

	cmdVerify := exec.Command(cliPath, verifyArgs...)
	cmdVerify.Dir = dir

	startVerify := time.Now()
	var startVMS runtime.MemStats
	if *verifyOnly {
		runtime.GC()
		runtime.ReadMemStats(&startVMS)
	}

	outVerify, errVerify := cmdVerify.CombinedOutput()
	verifyDuration := time.Since(startVerify)

	var endVMS runtime.MemStats
	if *verifyOnly {
		runtime.ReadMemStats(&endVMS)
	}

	// Expect exit code 1 (ExitRepairPossible)
	var exitErr *exec.ExitError
	if errVerify == nil {
		t.Fatal("expected verify to fail with exit code 1, got 0")
	} else if errorsIsExitError(errVerify, &exitErr) {
		if exitErr.ExitCode() != 1 {
			t.Fatalf("expected verify exit code 1, got %d\n%s", exitErr.ExitCode(), outVerify)
		}
	} else {
		t.Fatalf("verify failed with system error: %v", errVerify)
	}

	if *verifyOnly {
		t.Logf("Verify CLI Output:\n%s", outVerify)
		t.Log("================ VERIFY-ONLY PERFORMANCE RESULTS ================")
		t.Logf("Total Verify Duration  : %s", verifyDuration)
		t.Logf("Verification Speed     : %.2f MB/s", 18432.0/verifyDuration.Seconds())
		t.Logf("Memory Stats (Start RSS): %d MB", startVMS.Sys/(1024*1024))
		t.Logf("Memory Stats (End RSS)  : %d MB", endVMS.Sys/(1024*1024))
		t.Logf("Memory Delta (RSS Growth): %d MB", (endVMS.Sys-startVMS.Sys)/(1024*1024))
		t.Log("==========================================================")
		t.Log("Verification completed correctly. Halting test due to verify_only flag.")
		return // EXIT EARLY
	}

	t.Log("Verification completed correctly. Repair is verified to be possible.")

	// 4. Execute repair command using par2engine-cli (Record RSS and Duration)
	t.Log("Executing par2engine-cli repair...")
	runtime.GC()
	var startMS runtime.MemStats
	runtime.ReadMemStats(&startMS)

	var repairArgs []string
	if *cpuprofile != "" {
		absCPU := resolveProfilePath(*cpuprofile)
		repairArgs = append(repairArgs, "-cpuprofile", absCPU)
	}
	if *memprofile != "" {
		absMem := resolveProfilePath(*memprofile)
		repairArgs = append(repairArgs, "-memprofile", absMem)
	}
	repairArgs = append(repairArgs, "repair", par2Path)

	cmdRepair := exec.Command(cliPath, repairArgs...)
	cmdRepair.Dir = dir

	startRepair := time.Now()
	outRepair, errRepair := cmdRepair.CombinedOutput()
	repairDuration := time.Since(startRepair)

	var endMS runtime.MemStats
	runtime.ReadMemStats(&endMS)

	if errRepair != nil {
		t.Fatalf("repair failed: %v\n%s", errRepair, outRepair)
	}

	// Log metrics
	t.Logf("Repair CLI Output:\n%s", outRepair)
	t.Log("================ PERFORMANCE TEST RESULTS ================")
	t.Logf("Total Repair Duration  : %s", repairDuration)
	t.Logf("Reconstruction Speed   : %.2f MB/s", 18432.0/repairDuration.Seconds())
	t.Logf("Memory Stats (Start RSS): %d MB", startMS.Sys/(1024*1024))
	t.Logf("Memory Stats (End RSS)  : %d MB", endMS.Sys/(1024*1024))
	t.Logf("Memory Delta (RSS Growth): %d MB", (endMS.Sys-startMS.Sys)/(1024*1024))
	t.Log("==========================================================")

	// 5. Verify correctness of recovered files
	t.Log("Verifying repaired file checksums byte-for-byte...")
	postLargeHash := computeMD5(largeFilePath)
	if postLargeHash != origLargeHash {
		t.Fatal("repaired large-file.dat MD5 checksum mismatch!")
	}

	repaired3, err := os.ReadFile(filepath.Join(dir, "small-3.dat"))
	if err != nil {
		t.Fatal("repaired small-3.dat not found on disk!")
	}
	t.Logf("small-3: origLen=%d repLen=%d", len(smallOriginals["small-3.dat"]), len(repaired3))
	if len(repaired3) >= 16 {
		t.Logf("small-3 orig: %x", smallOriginals["small-3.dat"][:16])
		t.Logf("small-3 rep : %x", repaired3[:16])
	}
	if !bytes.Equal(repaired3, smallOriginals["small-3.dat"]) {
		t.Fatal("repaired small-3.dat is not identical to original!")
	}

	repaired7, err := os.ReadFile(filepath.Join(dir, "small-7.dat"))
	if err != nil {
		t.Fatal("repaired small-7.dat not found on disk!")
	}
	t.Logf("small-7: origLen=%d repLen=%d", len(smallOriginals["small-7.dat"]), len(repaired7))
	if len(repaired7) >= 16 {
		t.Logf("small-7 orig: %x", smallOriginals["small-7.dat"][:16])
		t.Logf("small-7 rep : %x", repaired7[:16])
	}
	if !bytes.Equal(repaired7, smallOriginals["small-7.dat"]) {
		t.Fatal("repaired small-7.dat is not identical to original!")
	}

	t.Log("PERFECT RECONSTRUCTION VERIFIED! All files are byte-for-byte restored.")
}

func resolveProfilePath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	pwd := os.Getenv("PWD")
	if pwd != "" {
		return filepath.Join(pwd, path)
	}
	abs, _ := filepath.Abs(path)
	return abs
}
