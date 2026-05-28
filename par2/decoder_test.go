package par2

import (
	"bytes"
	"context"
	"crypto/md5"
	"hash/crc32"
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
	defer func() { _ = d.Close() }()

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

// TestScanChunkCRCCollisionDoesNotSkipShard is a regression test for the bug
// where a CRC-only match at a non-shard-boundary position caused the scanner to
// jump forward by sliceByteCount, skipping the real shard that followed.
//
// Setup:
//   - sliceByteCount = 8
//   - chunk starts at absolute offset 6 (not a shard boundary)
//   - real shard 1 is at absolute offset 8, i.e. relative j=2 within this chunk
//   - the lookup table contains a false entry for the data at j=0 (wrong MD5)
//
// With the bug: CRC hit at j=0 → jump to j=8 → shard at j=2 skipped.
// With the fix:  CRC hit at j=0, MD5 wrong → slide j++ → reach j=2 via rolling CRC → shard found.
func TestScanChunkCRCCollisionDoesNotSkipShard(t *testing.T) {
	const sliceSize = 8

	// Deterministic file data: 24 bytes.
	data := make([]byte, 24)
	for i := range data {
		data[i] = byte(i*37 + 5)
	}

	tmp, err := os.CreateTemp(t.TempDir(), "scantest")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tmp.Close() }()
	if _, err := tmp.Write(data); err != nil {
		t.Fatal(err)
	}

	// Chunk covers absolute [6, 24). Within this chunk:
	//   j=0 → absolute 6  (NOT a shard boundary; 6 % 8 != 0)
	//   j=2 → absolute 8  (shard 1; 8 % 8 == 0)
	const chunkStart, chunkEnd = int64(6), int64(24)
	chunkData := data[chunkStart:chunkEnd]

	// Data that will be seen by the scanner at j=0 (the collision position).
	collisionSlice := chunkData[0:sliceSize]
	collisionCRC := crc32.ChecksumIEEE(collisionSlice)

	// Data that the scanner sees at j=2 (the real shard).
	const realJ = 2
	realSlice := chunkData[realJ : realJ+sliceSize]
	realCRC := crc32.ChecksumIEEE(realSlice)
	realMD5 := md5.Sum(realSlice)

	if collisionCRC == realCRC {
		t.Skip("test data produces identical CRCs at j=0 and j=2; adjust the seed")
	}

	var targetFileID FileID

	checksumMap := make(map[uint32][]checksumLocation)
	// False positive: j=0 CRC is in the table but with the wrong MD5.
	checksumMap[collisionCRC] = []checksumLocation{{
		fileID:     targetFileID,
		shardIndex: 99,
		md5Hash:    [16]byte{0xFF}, // intentionally wrong
	}}
	// Real shard 1 at absolute offset 8.
	checksumMap[realCRC] = []checksumLocation{{
		fileID:     targetFileID,
		shardIndex: 1,
		md5Hash:    realMD5,
	}}

	lookupTable := newCRCLookupTable(checksumMap)

	window, err := newCRC32Window(sliceSize)
	if err != nil {
		t.Fatal(err)
	}

	d := &Decoder{sliceByteCount: sliceSize, logger: slog.Default()}

	matchChan := make(chan matchEvent, 10)
	if err := d.scanChunk(context.Background(), tmp, targetFileID, window, chunkStart, chunkEnd, lookupTable, matchChan); err != nil {
		t.Fatalf("scanChunk: %v", err)
	}
	close(matchChan)

	var found bool
	for ev := range matchChan {
		if ev.shardIndex == 1 && ev.offset == chunkStart+realJ {
			found = true
		}
	}
	if !found {
		t.Error("shard 1 at absolute offset 8 was not found; CRC collision at j=0 may have caused it to be skipped")
	}
}

// TestDecoderEndToEndMultiChunk verifies that VerifyScans correctly finds all
// shards in files that span multiple 32 MB scan chunks. This exercises the
// cross-chunk-boundary scanning path that was affected by the CRC collision bug.
func TestDecoderEndToEndMultiChunk(t *testing.T) {
	_, ok := hasPar2()
	if !ok {
		t.Skip("par2 binary not found in PATH; skipping multi-chunk integration test")
	}

	dir := t.TempDir()

	// 40 MB file — large enough to cross the 32 MB scanChunkSize boundary.
	const fileSize = 40 * 1024 * 1024
	r := rand.New(rand.NewPCG(99, 99))
	fileData := make([]byte, fileSize)
	for i := range fileData {
		fileData[i] = byte(r.Uint32())
	}

	inputFile := filepath.Join(dir, "bigfile.dat")
	if err := os.WriteFile(inputFile, fileData, 0644); err != nil {
		t.Fatalf("write bigfile: %v", err)
	}

	// Use a 10 MB slice size (matching the real-world case that exposed the bug)
	// and generate enough parity blocks for a full integrity check.
	par2Path := filepath.Join(dir, "big.par2")
	out, err := exec.Command("par2", "c", "-s10485760", "-c4", par2Path, inputFile).CombinedOutput()
	if err != nil {
		t.Fatalf("par2 create: %v\n%s", err, out)
	}

	d, err := NewDecoder(context.Background(), par2Path, DecoderOptions{Logger: slog.Default()})
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	defer func() { _ = d.Close() }()

	if err := d.VerifyScans(context.Background(), nil); err != nil {
		t.Fatalf("VerifyScans: %v", err)
	}

	counts := d.ShardCounts()
	if counts.UnusableDataShardCount != 0 {
		t.Errorf("expected 0 unusable shards, got %d — a shard crossing a chunk boundary was likely missed",
			counts.UnusableDataShardCount)
	}
}

// TestAddCandidateFile verifies that a file with the wrong name is still
// recognised and used as a repair source when registered via AddCandidateFile.
func TestAddCandidateFile(t *testing.T) {
	_, ok := hasPar2()
	if !ok {
		t.Skip("par2 binary not found in PATH")
	}

	dir := t.TempDir()
	r := rand.New(rand.NewPCG(77, 77))
	fileData := make([]byte, 64*1024)
	for i := range fileData {
		fileData[i] = byte(r.Uint32())
	}

	// Write the file under its correct name and build a PAR2 set.
	correctName := filepath.Join(dir, "correct.dat")
	if err := os.WriteFile(correctName, fileData, 0644); err != nil {
		t.Fatal(err)
	}
	par2Path := filepath.Join(dir, "set.par2")
	out, err := exec.Command("par2", "c", "-s16384", "-c4", par2Path, correctName).CombinedOutput()
	if err != nil {
		t.Fatalf("par2 create: %v\n%s", err, out)
	}

	// Delete the correctly-named file and leave only a wrongly-named copy.
	wrongName := filepath.Join(dir, "wrong_name.dat")
	if err := os.WriteFile(wrongName, fileData, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(correctName); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	d, err := NewDecoder(ctx, par2Path, DecoderOptions{Logger: slog.Default()})
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	defer func() { _ = d.Close() }()

	// Without AddCandidateFile the correct file is reported missing.
	if err := d.VerifyScans(ctx, nil); err != nil {
		t.Fatalf("VerifyScans: %v", err)
	}
	if counts := d.ShardCounts(); counts.UnusableDataShardCount == 0 {
		t.Fatal("expected unusable shards before registering candidate, got 0")
	}

	// Register the wrongly-named file as a candidate and re-scan.
	if err := d.AddCandidateFile("wrong_name.dat"); err != nil {
		t.Fatalf("AddCandidateFile: %v", err)
	}
	if err := d.VerifyScans(ctx, nil); err != nil {
		t.Fatalf("VerifyScans with candidate: %v", err)
	}
	counts := d.ShardCounts()
	if counts.UnusableDataShardCount != 0 {
		t.Errorf("expected 0 unusable shards after registering candidate, got %d", counts.UnusableDataShardCount)
	}
}

// TestRenameMisnamedFile verifies that a file with the wrong name is detected
// during verification and renamed (not reconstructed) during repair.
func TestRenameMisnamedFile(t *testing.T) {
	_, ok := hasPar2()
	if !ok {
		t.Skip("par2 binary not found in PATH")
	}

	dir := t.TempDir()
	r := rand.New(rand.NewPCG(88, 88))
	fileData := make([]byte, 64*1024)
	for i := range fileData {
		fileData[i] = byte(r.Uint32())
	}

	// Write the file under its correct name and build a PAR2 set.
	correctName := filepath.Join(dir, "correct.dat")
	if err := os.WriteFile(correctName, fileData, 0644); err != nil {
		t.Fatal(err)
	}
	par2Path := filepath.Join(dir, "set.par2")
	out, err := exec.Command("par2", "c", "-s16384", "-c4", par2Path, correctName).CombinedOutput()
	if err != nil {
		t.Fatalf("par2 create: %v\n%s", err, out)
	}

	// Rename: delete correct name, leave only the wrong name.
	wrongName := filepath.Join(dir, "wrong_name.dat")
	if err := os.Rename(correctName, wrongName); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	d, err := NewDecoder(ctx, par2Path, DecoderOptions{Logger: slog.Default()})
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	defer func() { _ = d.Close() }()

	// Register the wrongly-named file as a candidate.
	if err := d.AddCandidateFile("wrong_name.dat"); err != nil {
		t.Fatalf("AddCandidateFile: %v", err)
	}

	// Verify: should detect the rename candidate, NOT report as damaged.
	if err := d.VerifyScans(ctx, nil); err != nil {
		t.Fatalf("VerifyScans: %v", err)
	}

	// All shards should be usable (found in the candidate).
	counts := d.ShardCounts()
	if counts.UnusableDataShardCount != 0 {
		t.Fatalf("expected 0 unusable shards, got %d", counts.UnusableDataShardCount)
	}

	// The file should have RenameSource set, not HashMismatch.
	d.mu.Lock()
	var renameFound bool
	for _, fd := range d.protectedFiles {
		state := d.fileIntegrity[fd.FileID]
		if state.RenameSource != "" {
			renameFound = true
			if state.HashMismatch {
				t.Error("file with RenameSource should not have HashMismatch set")
			}
		}
	}
	d.mu.Unlock()
	if !renameFound {
		t.Fatal("expected at least one file with RenameSource set")
	}

	// Repair: should rename, not reconstruct.
	progressChan := make(chan Progress, 10)
	go func() {
		for range progressChan {
		}
	}()

	if err := d.Repair(ctx, progressChan); err != nil {
		t.Fatalf("Repair: %v", err)
	}

	// Assert: correct name exists with original content.
	repaired, err := os.ReadFile(correctName)
	if err != nil {
		t.Fatalf("correct.dat should exist after repair: %v", err)
	}
	if !bytes.Equal(repaired, fileData) {
		t.Fatal("repaired file content does not match original")
	}

	// Assert: wrong name is gone.
	if _, err := os.Stat(wrongName); !os.IsNotExist(err) {
		t.Fatal("wrong_name.dat should not exist after rename")
	}

	// Re-verify: should be fully healthy now.
	d2, err := NewDecoder(ctx, par2Path, DecoderOptions{Logger: slog.Default()})
	if err != nil {
		t.Fatalf("NewDecoder re-verify: %v", err)
	}
	defer func() { _ = d2.Close() }()
	if err := d2.VerifyScans(ctx, nil); err != nil {
		t.Fatalf("VerifyScans re-verify: %v", err)
	}
	counts2 := d2.ShardCounts()
	if counts2.RepairNeeded() {
		t.Fatalf("expected no repair needed after rename, got %d unusable shards", counts2.UnusableDataShardCount)
	}
}

func TestDecoderMaliciousIFSCPacket(t *testing.T) {
	dir := t.TempDir()
	dummyFile := filepath.Join(dir, "dummy.dat")
	if err := os.WriteFile(dummyFile, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
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
	defer func() { _ = d.Close() }()

	fd := FileDescPacket{
		FileID:    FileID{0x01},
		Filename:  "dummy.dat",
		ByteCount: 11,
	}
	d.protectedFiles = append(d.protectedFiles, fd)

	maliciousFID := FileID{0x02}
	d.fileChecksums[maliciousFID] = &IFSCPacket{
		FileID: maliciousFID,
		ChecksumPairs: []ChecksumPair{
			{
				MD5:   [16]byte{0xAA},
				CRC32: [4]byte{0xBB},
			},
		},
	}
	d.fileChecksums[fd.FileID] = &IFSCPacket{
		FileID: fd.FileID,
		ChecksumPairs: []ChecksumPair{
			{
				MD5:   [16]byte{0xCC},
				CRC32: [4]byte{0xDD},
			},
		},
	}

	d.sliceByteCount = 11

	ctx := context.Background()
	err = d.VerifyScans(ctx, nil)
	if err != nil {
		t.Fatalf("VerifyScans failed: %v", err)
	}
}
