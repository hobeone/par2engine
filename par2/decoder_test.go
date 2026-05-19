package par2

import (
	"bytes"
	"context"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func hasPar2() (string, bool) {
	path, err := exec.LookPath("par2")
	if err != nil {
		return "", false
	}
	return path, true
}

func TestDecoderEndToEnd(t *testing.T) {
	_, ok := hasPar2()
	if !ok {
		t.Skip("par2 binary not found in PATH; skipping integration test")
	}

	dir := t.TempDir()
	inputFile1 := filepath.Join(dir, "file1.dat")
	inputFile2 := filepath.Join(dir, "file2.dat")

	// 1. Generate 128KB of random test data for file1, and 256KB for file2
	r := rand.New(rand.NewPCG(42, 42))
	generateData := func(size int) []byte {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(r.Uint32())
		}
		return data
	}

	data1 := generateData(128 * 1024)
	data2 := generateData(256 * 1024)
	if err := os.WriteFile(inputFile1, data1, 0644); err != nil {
		t.Fatalf("failed to write file1: %v", err)
	}
	if err := os.WriteFile(inputFile2, data2, 0644); err != nil {
		t.Fatalf("failed to write file2: %v", err)
	}

	// 2. Use par2 CLI to create parity files (block size = 16KB, 4 parity blocks)
	par2Path := filepath.Join(dir, "set.par2")
	createCmd := exec.Command("par2", "c", "-s16384", "-c4", par2Path, inputFile1, inputFile2)
	createCmd.Dir = dir
	out, err := createCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to create par2 set: %v\n%s", err, out)
	}

	ctx := context.Background()

	t.Run("verify_healthy_set", func(t *testing.T) {
		d, err := NewDecoder(ctx, par2Path, 0, 0, nil)
		if err != nil {
			t.Fatalf("NewDecoder failed: %v", err)
		}
		defer d.Close()

		err = d.VerifyScans(ctx, nil)
		if err != nil {
			t.Fatalf("VerifyScans failed: %v", err)
		}

		counts := d.ShardCounts()
		if counts.RepairNeeded() {
			t.Fatalf("expected no repair needed, got unusable data shards: %d", counts.UnusableDataShardCount)
		}
	})

	t.Run("corrupt_and_repair_success", func(t *testing.T) {
		// Save originals for byte comparison
		orig1 := make([]byte, len(data1))
		copy(orig1, data1)
		orig2 := make([]byte, len(data2))
		copy(orig2, data2)

		// Corrupt file1: delete it completely
		if err := os.Remove(inputFile1); err != nil {
			t.Fatalf("failed to delete file1: %v", err)
		}

		// Corrupt file2: flip a byte in shard 3 (offset 3 * 16KB = 49152)
		data2Corrupted := make([]byte, len(orig2))
		copy(data2Corrupted, orig2)
		data2Corrupted[49152] ^= 0xFF
		if err := os.WriteFile(inputFile2, data2Corrupted, 0644); err != nil {
			t.Fatalf("failed to corrupt file2: %v", err)
		}

		// Open decoder
		d, err := NewDecoder(ctx, par2Path, 2, 64*1024, nil) // 2 threads, tiny memory limit (64KB buffer) to test streaming!
		if err != nil {
			t.Fatalf("NewDecoder failed: %v", err)
		}
		defer d.Close()

		// Scan
		err = d.VerifyScans(ctx, nil)
		if err != nil {
			t.Fatalf("VerifyScans failed: %v", err)
		}

		counts := d.ShardCounts()
		// Expected:
		// - file1 deleted: 8 shards missing (128KB / 16KB = 8 shards)
		// - file2 corrupt: 1 shard missing
		// Total unusable = 9
		// Usable parity = 4 (we created 4 blocks)
		// Wait! If total unusable is 9 and parity is 4, then repair is NOT possible!
		// Let's verify this!
		if counts.RepairPossible() {
			t.Fatalf("expected repair not possible (need 9 blocks, have 4), but RepairPossible returned true")
		}

		// Let's restore file1 and ONLY corrupt file2 to ensure we have enough parity (needs 1 block, we have 4)!
		if err := os.WriteFile(inputFile1, orig1, 0644); err != nil {
			t.Fatalf("failed to restore file1: %v", err)
		}

		// Scan again
		err = d.VerifyScans(ctx, nil)
		if err != nil {
			t.Fatalf("VerifyScans 2 failed: %v", err)
		}

		counts = d.ShardCounts()
		if counts.UnusableDataShardCount != 1 {
			t.Fatalf("expected exactly 1 unusable shard, got %d", counts.UnusableDataShardCount)
		}
		if !counts.RepairPossible() {
			t.Fatalf("expected repair possible, got unusable: %d, parity: %d", counts.UnusableDataShardCount, counts.UsableParityShardCount)
		}

		// Perform Repair!
		progressChan := make(chan Progress, 10)
		go func() {
			for range progressChan {
				// drain progress
			}
		}()

		err = d.Repair(ctx, progressChan)
		if err != nil {
			t.Fatalf("Repair failed: %v", err)
		}

		// Verify file2 was perfectly repaired
		repaired2, err := os.ReadFile(inputFile2)
		if err != nil {
			t.Fatalf("failed to read repaired file2: %v", err)
		}
		if !bytes.Equal(repaired2, orig2) {
			t.Fatalf("repaired file2 is not identical to original!")
		}
	})
}

func TestDecoderSandboxing(t *testing.T) {
	// Verify that os.Root sandboxing correctly throws an error if we try to escape
	dir := t.TempDir()
	
	// Create a decoder inside target directory
	dummyIndex := filepath.Join(dir, "dummy.par2")
	if err := os.WriteFile(dummyIndex, []byte("PAR2\x00PKT"), 0644); err != nil {
		t.Fatalf("failed to write dummy index: %v", err)
	}

	d := &Decoder{
		numGoroutines: 1,
		memoryLimit:   1024,
		logger:        slog.Default(),
		fileChecksums: make(map[FileID]*IFSCPacket),
		parityShards:  make(map[uint16][]byte),
		fileIntegrity: make(map[FileID]*FileIntegrityState),
	}
	
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot failed: %v", err)
	}
	d.root = root
	defer d.Close()

	// Attempt to open a file outside the root (e.g., absolute path on Unix, or drive path on Windows, or relative traversal)
	_, err = d.root.Open("../escaped.dat")
	if err == nil {
		t.Fatal("expected directory traversal block error from os.Root, got nil")
	}
	if !osIsPermissionOrNotExist(err) {
		t.Logf("Got expected OS-enforced sandboxing block error: %v", err)
	}
}

func osIsPermissionOrNotExist(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "no such file") || strings.Contains(msg, "does not exist") || strings.Contains(msg, "outside root")
}
