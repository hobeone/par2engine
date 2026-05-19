//go:build perf

package tests

import (
	"bytes"
	"crypto/md5"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var cpuprofile = flag.String("perf.cpuprofile", "", "write cpu profile of repair to file")
var memprofile = flag.String("perf.memprofile", "", "write mem profile of repair to file")


func TestPerfLarge(t *testing.T) {
	fixturesDir := "/usr/local/google/home/hobe/software/par2cmdline/tests"
	if _, err := os.Stat(fixturesDir); err != nil {
		t.Skip("par2cmdline workspace tests folder not found, skipping performance E2E test")
	}

	dir := "/usr/local/google/home/hobe/software/par2engine/perf_workspace"
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("failed to create perf workspace: %v", err)
	}
	defer os.RemoveAll(dir)

	t.Logf("Performance test workspace initialized at %s", dir)

	// 1. Generate 16MB buffer of random bytes
	t.Log("Generating 16MB pattern buffer...")
	r := rand.New(rand.NewPCG(42, 42))
	pattern := make([]byte, 16*1024*1024)
	for i := range pattern {
		pattern[i] = byte(r.Uint32())
	}

	// 2. Write 18GB semi-random file (16MB written 1152 times)
	largeFilePath := filepath.Join(dir, "large-file.dat")
	t.Log("Writing 18GB large-file.dat sequentially...")
	largeFile, err := os.OpenFile(largeFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("failed to create large file: %v", err)
	}

	startWrite := time.Now()
	for i := 0; i < 1152; i++ {
		_, err = largeFile.Write(pattern)
		if err != nil {
			largeFile.Close()
			t.Fatalf("failed writing chunk %d to large-file: %v", i, err)
		}
	}
	largeFile.Close()
	t.Logf("Successfully wrote 18GB large-file.dat in %s", time.Since(startWrite))

	// 3. Generate 10 small files (sizes 1-4MB)
	t.Log("Generating 10 small files...")
	smallOriginals := make(map[string][]byte)
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("small-%d.dat", i)
		size := (1 + rand.IntN(4)) * 1024 * 1024
		data := make([]byte, size)
		for j := range data {
			data[j] = byte(r.Uint32())
		}
		smallOriginals[name] = data
		err = os.WriteFile(filepath.Join(dir, name), data, 0644)
		if err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
	}

	// 4. Calculate pre-corruption MD5 hashes of the files
	t.Log("Computing pre-corruption reference MD5 hashes...")
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

	// 5. Create PAR2 set using canonical par2 CLI (Block Size = 4MB, Parity Block Count = 230)
	t.Log("Invoking host's par2 CLI to generate recovery set (BlockSize=4MB, Count=230)...")
	par2Path := filepath.Join(dir, "set.par2")
	createCmd := exec.Command("par2", "c", "-s4194304", "-c230", par2Path, largeFilePath)
	// Append small files
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("small-%d.dat", i)
		createCmd.Args = append(createCmd.Args, filepath.Join(dir, name))
	}
	createCmd.Dir = dir

	startCreate := time.Now()
	out, err := createCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to create par2 set via C++ par2: %v\n%s", err, out)
	}
	t.Logf("PAR2 set created successfully in %s", time.Since(startCreate))

	// 6. Corrupt files:
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

	// 7. Execute verify command using par2engine-cli
	t.Log("Executing par2engine-cli verify...")
	cmdVerify := exec.Command(cliPath, "verify", par2Path)
	cmdVerify.Dir = dir
	outVerify, errVerify := cmdVerify.CombinedOutput()

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
	t.Log("Verification completed correctly. Repair is verified to be possible.")

	// 8. Execute repair command using par2engine-cli (Record RSS and Duration)
	t.Log("Executing par2engine-cli repair...")
	runtime.GC()
	var startMS runtime.MemStats
	runtime.ReadMemStats(&startMS)

	repairArgs := []string{"repair"}
	if *cpuprofile != "" {
		absCPU, _ := filepath.Abs(*cpuprofile)
		repairArgs = append(repairArgs, "-cpuprofile", absCPU)
	}
	if *memprofile != "" {
		absMem, _ := filepath.Abs(*memprofile)
		repairArgs = append(repairArgs, "-memprofile", absMem)
	}
	repairArgs = append(repairArgs, par2Path)

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

	// 9. Verify correctness of recovered files
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
