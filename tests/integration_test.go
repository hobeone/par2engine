package tests

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIntegrationWithCanonicalFixtures(t *testing.T) {
	// Resolve absolute path to par2cmdline test archives in the workspace
	fixturesDir := "/usr/local/google/home/hobe/software/par2cmdline/tests"
	flatDataArchive := filepath.Join(fixturesDir, "flatdata.tar.gz")
	par2DataArchive := filepath.Join(fixturesDir, "flatdata-par2files.tar.gz")

	// Verify archives exist
	if _, err := os.Stat(flatDataArchive); err != nil {
		t.Skipf("par2cmdline test archives not found in workspace, skipping: %v", err)
	}

	dir := t.TempDir()

	// Copy and extract flatdata.tar.gz in the temp directory
	extract := func(archive string) {
		cmd := exec.Command("tar", "-xzf", archive)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("failed to extract %s: %v\n%s", filepath.Base(archive), err, out)
		}
	}

	extract(flatDataArchive)
	extract(par2DataArchive)

	// Debug print the directory contents
	entries, _ := os.ReadDir(dir)
	t.Log("Files in temp test dir:")
	for _, e := range entries {
		t.Logf("  %s (isDir=%v)", e.Name(), e.IsDir())
	}

	// Resolve absolute path to our par2engine-cli binary
	cliPath, err := filepath.Abs("../par2engine-cli")
	if err != nil {
		t.Fatalf("failed to resolve CLI binary path: %v", err)
	}

	// Verify CLI exists (if not built, compile it)
	if _, err := os.Stat(cliPath); err != nil {
		t.Log("par2engine-cli binary not found, building now...")
		buildCmd := exec.Command("go", "build", "-o", cliPath, "../cmd/gopar")
		out, err := buildCmd.CombinedOutput()
		if err != nil {
			t.Fatalf("failed to build CLI: %v\n%s", err, out)
		}
	}

	t.Run("canonical_verify_healthy_set", func(t *testing.T) {
		cmd := exec.Command(cliPath, "verify", "testdata.par2")
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("verify healthy set failed: %v\n%s", err, out)
		}
		// Check exit code is 0 (ExitSuccess)
		var exitErr *exec.ExitError
		if err != nil && errorsIsExitError(err, &exitErr) {
			t.Fatalf("verify healthy set returned exit code %d, want 0\n%s", exitErr.ExitCode(), out)
		}
	})

	t.Run("canonical_verify_and_repair_corrupted_set", func(t *testing.T) {
		// Make copies of test-1.data and test-3.data before corruption
		orig1, err := os.ReadFile(filepath.Join(dir, "test-1.data"))
		if err != nil {
			t.Fatalf("failed to read test-1: %v", err)
		}
		orig3, err := os.ReadFile(filepath.Join(dir, "test-3.data"))
		if err != nil {
			t.Fatalf("failed to read test-3: %v", err)
		}

		// 1. Corrupt files just like par2cmdline's "test3" does:
		// Delete test-1.data
		if err := os.Remove(filepath.Join(dir, "test-1.data")); err != nil {
			t.Fatalf("failed to delete test-1: %v", err)
		}
		// Flip a byte in test-3.data at offset 100
		corrupted3 := make([]byte, len(orig3))
		copy(corrupted3, orig3)
		corrupted3[100] ^= 0xFF
		if err := os.WriteFile(filepath.Join(dir, "test-3.data"), corrupted3, 0644); err != nil {
			t.Fatalf("failed to corrupt test-3: %v", err)
		}

		// Debug print the directory contents before verify in second subtest
		entriesSub, _ := os.ReadDir(dir)
		t.Log("Files in temp test dir before verify (subtest):")
		for _, e := range entriesSub {
			t.Logf("  %s (isDir=%v)", e.Name(), e.IsDir())
		}

		// 2. Run verify on corrupted set
		cmdVerify := exec.Command(cliPath, "verify", "testdata.par2")
		cmdVerify.Dir = dir
		outVerify, errVerify := cmdVerify.CombinedOutput()
		
		// Expect exit code 1 (ExitRepairPossible)
		var exitErr *exec.ExitError
		if errVerify == nil {
			t.Fatal("expected verify corrupted set to fail with exit code 1, got 0")
		} else if errorsIsExitError(errVerify, &exitErr) {
			if exitErr.ExitCode() != 1 {
				t.Fatalf("expected verify exit code 1, got %d\n%s", exitErr.ExitCode(), outVerify)
			}
		} else {
			t.Fatalf("verify failed with system error: %v", errVerify)
		}

		// 3. Run repair on corrupted set
		cmdRepair := exec.Command(cliPath, "repair", "testdata.par2")
		cmdRepair.Dir = dir
		outRepair, errRepair := cmdRepair.CombinedOutput()
		if errRepair != nil {
			t.Fatalf("repair failed: %v\n%s", errRepair, outRepair)
		}
		t.Logf("Repair CLI Output:\n%s", outRepair)
		// 4. Verify files are restored perfectly
		repaired1, err := os.ReadFile(filepath.Join(dir, "test-1.data"))
		if err != nil {
			t.Fatalf("failed to read repaired test-1: %v", err)
		}
		repaired3, err := os.ReadFile(filepath.Join(dir, "test-3.data"))
		if err != nil {
			t.Fatalf("failed to read repaired test-3: %v", err)
		}

		t.Logf("test-1: origLen=%d repLen=%d", len(orig1), len(repaired1))
		t.Logf("test-3: origLen=%d repLen=%d", len(orig3), len(repaired3))
		if len(orig1) > 16 && len(repaired1) > 16 {
			t.Logf("test-1 orig: %x", orig1[:16])
			t.Logf("test-1 rep : %x", repaired1[:16])
		}
		if len(orig3) > 16 && len(repaired3) > 16 {
			t.Logf("test-3 orig: %x", orig3[:16])
			t.Logf("test-3 rep : %x", repaired3[:16])
		}

		if !bytes.Equal(repaired1, orig1) {
			t.Fatal("repaired test-1.data is not identical to original")
		}
		if !bytes.Equal(repaired3, orig3) {
			t.Fatal("repaired test-3.data is not identical to original")
		}
	})
}

func errorsIsExitError(err error, target **exec.ExitError) bool {
	if err == nil {
		return false
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		*target = exitErr
		return true
	}
	return false
}
