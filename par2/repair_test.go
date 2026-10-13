package par2

import (
	"bytes"
	"context"
	"crypto/md5"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidateParityShards(t *testing.T) {
	t.Run("valid_shards_no_error", func(t *testing.T) {
		d := &Decoder{
			sliceByteCount: 8,
			parityShards:   map[uint16][]byte{0: make([]byte, 8), 1: make([]byte, 8)},
		}
		if err := d.validateParityShards(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("short_shard_returns_error", func(t *testing.T) {
		d := &Decoder{
			sliceByteCount: 8,
			parityShards:   map[uint16][]byte{0: make([]byte, 8), 1: make([]byte, 4)},
		}
		if err := d.validateParityShards(); err == nil {
			t.Error("expected error for parity shard with wrong length, got nil")
		}
	})

	t.Run("empty_map_no_error", func(t *testing.T) {
		d := &Decoder{sliceByteCount: 8, parityShards: map[uint16][]byte{}}
		if err := d.validateParityShards(); err != nil {
			t.Errorf("unexpected error for empty shard map: %v", err)
		}
	})
}

func TestComputeChunkSize(t *testing.T) {
	d := &Decoder{memoryLimit: 16 * 1024 * 1024, sliceByteCount: 4096}

	t.Run("zero_denominator_returns_error", func(t *testing.T) {
		if _, err := d.computeChunkSize(0, 0); err == nil {
			t.Error("expected error for zero denominator, got nil")
		}
	})

	t.Run("result_is_16_byte_aligned", func(t *testing.T) {
		size, err := d.computeChunkSize(10, 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if size%16 != 0 {
			t.Errorf("chunk size %d is not 16-byte aligned", size)
		}
		if size <= 0 {
			t.Errorf("chunk size must be positive, got %d", size)
		}
	})

	t.Run("result_capped_at_slice_byte_count", func(t *testing.T) {
		huge := &Decoder{memoryLimit: 1 << 30, sliceByteCount: 4096}
		size, err := huge.computeChunkSize(1, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if size > int64(huge.sliceByteCount) {
			t.Errorf("chunk size %d exceeds sliceByteCount %d", size, huge.sliceByteCount)
		}
	})
}

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
		d, err := NewDecoder(ctx, par2Path, DecoderOptions{})
		if err != nil {
			t.Fatalf("NewDecoder failed: %v", err)
		}
		defer func() { _ = d.Close() }()

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
		d, err := NewDecoder(ctx, par2Path, DecoderOptions{NumGoroutines: 2, MemoryLimit: 64 * 1024}) // 2 threads, tiny memory limit (64KB buffer) to test streaming!
		if err != nil {
			t.Fatalf("NewDecoder failed: %v", err)
		}
		defer func() { _ = d.Close() }()

		// Scan
		err = d.VerifyScans(ctx, nil)
		if err != nil {
			t.Fatalf("VerifyScans failed: %v", err)
		}

		counts := d.ShardCounts()
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

// installTestFile describes one protected file for newInstallTestPipeline: its
// current bytes on disk (mode 0600), the bytes rebuilt for it, and the hash
// install checks those rebuilt bytes against.
type installTestFile struct {
	name     string
	original []byte
	rebuilt  []byte
	wantHash [16]byte
}

// newInstallTestPipeline returns a pipeline over a fresh sandbox holding each
// file's original bytes, with an output temp file per file holding its rebuilt
// bytes followed by zero padding that install must truncate away.
func newInstallTestPipeline(t *testing.T, files ...installTestFile) (*repairPipeline, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	d := &Decoder{root: root}
	p := &repairPipeline{
		d:         d,
		plan:      &repairPlan{needsWrite: make(map[string]bool)},
		sources:   make(map[string]*os.File),
		outputs:   make(map[string]*os.File),
		tempNames: make(map[string]string),
	}
	for i, tf := range files {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(tf.name)), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, tf.name), tf.original, 0600); err != nil {
			t.Fatal(err)
		}
		d.protectedFiles = append(d.protectedFiles, FileDescPacket{
			FileID: FileID{byte(i + 1)}, Filename: tf.name, ByteCount: len(tf.rebuilt), Hash: tf.wantHash,
		})
		p.plan.needsWrite[tf.name] = true
		f, err := p.getOutput(tf.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(append(append([]byte{}, tf.rebuilt...), 0, 0, 0)); err != nil {
			t.Fatal(err)
		}
	}
	return p, dir
}

func assertFileContents(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s = %q, want %q", filepath.Base(path), got, want)
	}
}

// TestRepairPipelineInstall runs each case with the files at the top of the
// sandbox and again inside a nested directory, where the temp file is created
// beside its target in that directory.
func TestRepairPipelineInstall(t *testing.T) {
	for _, layout := range []struct{ name, dir string }{
		{"top_level", ""},
		{"nested_dir", filepath.Join("sub", "dir")},
	} {
		t.Run(layout.name, func(t *testing.T) {
			testRepairPipelineInstall(t, filepath.Join(layout.dir, "a.dat"), filepath.Join(layout.dir, "b.dat"))
		})
	}
}

func testRepairPipelineInstall(t *testing.T, aName, bName string) {
	original := []byte("old contents")
	rebuilt := []byte("rebuilt contents")

	t.Run("hash_match_installs_and_keeps_mode", func(t *testing.T) {
		p, dir := newInstallTestPipeline(t, installTestFile{aName, original, rebuilt, md5.Sum(rebuilt)})
		// The temp file sits beside its target, so the final rename never
		// crosses a directory and so never crosses a filesystem.
		if got := filepath.Dir(p.tempNames[aName]); got != filepath.Dir(aName) {
			t.Errorf("temp file for %s is in %q, want %q", aName, got, filepath.Dir(aName))
		}
		if err := p.install(); err != nil {
			t.Fatalf("install failed: %v", err)
		}
		p.close()

		assertFileContents(t, filepath.Join(dir, aName), rebuilt)
		info, err := os.Stat(filepath.Join(dir, aName))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Errorf("%s mode = %v, want 0600 kept from the replaced file", aName, info.Mode().Perm())
		}
		assertNoRepairTempFiles(t, dir)
	})

	t.Run("hash_mismatch_leaves_original_and_no_temp", func(t *testing.T) {
		p, dir := newInstallTestPipeline(t, installTestFile{aName, original, rebuilt, md5.Sum([]byte("something else"))})
		if err := p.install(); err == nil {
			t.Fatal("install succeeded despite a hash mismatch")
		}
		p.close()

		assertFileContents(t, filepath.Join(dir, aName), original)
		assertNoRepairTempFiles(t, dir)
	})

	// One file passing its hash must not be installed while another fails:
	// a hash mismatch anywhere installs nothing.
	t.Run("one_mismatch_installs_no_file", func(t *testing.T) {
		otherRebuilt := []byte("other rebuilt")
		p, dir := newInstallTestPipeline(t,
			installTestFile{aName, original, rebuilt, md5.Sum(rebuilt)},
			installTestFile{bName, original, otherRebuilt, md5.Sum([]byte("something else"))},
		)
		if err := p.install(); err == nil {
			t.Fatal("install succeeded despite a hash mismatch")
		}
		p.close()

		assertFileContents(t, filepath.Join(dir, aName), original)
		assertFileContents(t, filepath.Join(dir, bName), original)
		assertNoRepairTempFiles(t, dir)
	})

	// A file marked for writing that never got an output must fail the repair
	// rather than be reported as rebuilt.
	t.Run("file_without_output_fails", func(t *testing.T) {
		p, dir := newInstallTestPipeline(t, installTestFile{aName, original, rebuilt, md5.Sum(rebuilt)})
		p.plan.needsWrite["never-written.dat"] = true
		if err := p.install(); err == nil {
			t.Fatal("install succeeded although a file marked for writing has no output")
		}
		p.close()

		assertFileContents(t, filepath.Join(dir, aName), original)
		assertNoRepairTempFiles(t, dir)
	})
}

// TestRepairPipelineGetOutputLeavesExistingFilesAlone pins that the temp file
// is a new file: a file already in the directory whose name looks like a temp
// file (here, one left by an older version) is not opened, truncated or
// removed.
func TestRepairPipelineGetOutputLeavesExistingFilesAlone(t *testing.T) {
	dir := t.TempDir()
	existing := []byte("not ours")
	for _, name := range []string{"x.par2engine-tmp", "x" + repairTempMarker + "AAAAAAAAAAAAAAAA" + repairTempExt} {
		if err := os.WriteFile(filepath.Join(dir, name), existing, 0644); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	p := &repairPipeline{
		d:         &Decoder{root: root},
		sources:   make(map[string]*os.File),
		outputs:   make(map[string]*os.File),
		tempNames: make(map[string]string),
	}

	f, err := p.getOutput("x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	p.close()

	assertFileContents(t, filepath.Join(dir, "x.par2engine-tmp"), existing)
	assertFileContents(t, filepath.Join(dir, "x"+repairTempMarker+"AAAAAAAAAAAAAAAA"+repairTempExt), existing)
	if _, err := os.Stat(filepath.Join(dir, p.tempNames["x"])); !os.IsNotExist(err) {
		t.Errorf("close left this repair's temp file behind (stat err %v)", err)
	}
}

func TestShardCountsFilesNeedingRebuild(t *testing.T) {
	located := []shardLocation{{FileID: FileID{9}, Offset: 100}}
	d := &Decoder{fileIntegrity: map[FileID]*fileIntegrityState{
		{1}: {Verified: true, ShardLocations: located},
		{2}: {Missing: true, ShardLocations: located},
		{3}: {SizeMismatch: true, ShardLocations: located},
		{4}: {HashMismatch: true, ShardLocations: located},
		// A pending rename is counted as a rename, not also as a rebuild.
		{5}: {HashMismatch: true, RenameSource: "other.dat", ShardLocations: located},
	}}

	sc := d.ShardCounts()
	if sc.UnusableDataShardCount != 0 {
		t.Fatalf("UnusableDataShardCount = %d, want 0", sc.UnusableDataShardCount)
	}
	if sc.FilesNeedingRebuild != 3 {
		t.Errorf("FilesNeedingRebuild = %d, want 3", sc.FilesNeedingRebuild)
	}
	if sc.RenamesNeeded != 1 {
		t.Errorf("RenamesNeeded = %d, want 1", sc.RenamesNeeded)
	}
	if !sc.RepairNeeded() || !sc.RepairPossible() {
		t.Errorf("RepairNeeded=%v RepairPossible=%v, want both true", sc.RepairNeeded(), sc.RepairPossible())
	}
}
