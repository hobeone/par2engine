package par2

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"hash/crc32"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBlockScannerSetScanErr confirms first-write-wins: a second error must not
// overwrite the original so the caller sees the root cause, not a later symptom.
func TestBlockScannerSetScanErr(t *testing.T) {
	s := &blockScanner{}
	first := errors.New("root cause")
	s.setScanErr(first)
	s.setScanErr(errors.New("later symptom"))
	if s.scanErr != first {
		t.Errorf("expected first error to be preserved, got %v", s.scanErr)
	}
}

// TestScanCandidateFileNotFound confirms that a missing candidate file is
// silently skipped (ErrNotExist → log warning + return nil, not an error).
func TestScanCandidateFileNotFound(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	scanner := &blockScanner{
		d:           &Decoder{sliceByteCount: 8, logger: slog.Default(), root: root},
		ctx:         context.Background(),
		sem:         make(chan struct{}, 1),
		lookupTable: newCRCLookupTable(nil),
		matchChan:   make(chan matchEvent, 5),
	}
	defer func() { _ = root.Close() }()

	if err := scanner.scanCandidateFile("no_such_file.dat", FileID{}); err != nil {
		t.Errorf("expected nil for missing candidate, got %v", err)
	}
}

func hasPar2Cmd() bool {
	_, err := exec.LookPath("par2")
	return err == nil
}

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

	scanner := &blockScanner{
		d:           &Decoder{sliceByteCount: sliceSize, logger: slog.Default()},
		ctx:         context.Background(),
		window:      window,
		lookupTable: lookupTable,
		matchChan:   make(chan matchEvent, 10),
	}
	if err := scanner.scanChunk(tmp, targetFileID, chunkStart, chunkEnd); err != nil {
		t.Fatalf("scanChunk: %v", err)
	}
	close(scanner.matchChan)

	var found bool
	for ev := range scanner.matchChan {
		if ev.shardIndex == 1 && ev.offset == chunkStart+realJ {
			found = true
		}
	}
	if !found {
		t.Error("shard 1 at absolute offset 8 was not found; CRC collision at j=0 may have caused it to be skipped")
	}
}

func TestDecoderEndToEndMultiChunk(t *testing.T) {
	if !hasPar2Cmd() {
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

func TestAddCandidateFile(t *testing.T) {
	if !hasPar2Cmd() {
		t.Skip("par2 binary not found in PATH")
	}

	dir := t.TempDir()
	r := rand.New(rand.NewPCG(77, 77))
	fileData := make([]byte, 64*1024)
	for i := range fileData {
		fileData[i] = byte(r.Uint32())
	}

	correctName := filepath.Join(dir, "correct.dat")
	if err := os.WriteFile(correctName, fileData, 0644); err != nil {
		t.Fatal(err)
	}
	par2Path := filepath.Join(dir, "set.par2")
	out, err := exec.Command("par2", "c", "-s16384", "-c4", par2Path, correctName).CombinedOutput()
	if err != nil {
		t.Fatalf("par2 create: %v\n%s", err, out)
	}

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

	if err := d.VerifyScans(ctx, nil); err != nil {
		t.Fatalf("VerifyScans: %v", err)
	}
	if counts := d.ShardCounts(); counts.UnusableDataShardCount == 0 {
		t.Fatal("expected unusable shards before registering candidate, got 0")
	}

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

func TestRenameMisnamedFile(t *testing.T) {
	if !hasPar2Cmd() {
		t.Skip("par2 binary not found in PATH")
	}

	dir := t.TempDir()
	r := rand.New(rand.NewPCG(88, 88))
	fileData := make([]byte, 64*1024)
	for i := range fileData {
		fileData[i] = byte(r.Uint32())
	}

	correctName := filepath.Join(dir, "correct.dat")
	if err := os.WriteFile(correctName, fileData, 0644); err != nil {
		t.Fatal(err)
	}
	par2Path := filepath.Join(dir, "set.par2")
	out, err := exec.Command("par2", "c", "-s16384", "-c4", par2Path, correctName).CombinedOutput()
	if err != nil {
		t.Fatalf("par2 create: %v\n%s", err, out)
	}

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

	if err := d.AddCandidateFile("wrong_name.dat"); err != nil {
		t.Fatalf("AddCandidateFile: %v", err)
	}

	if err := d.VerifyScans(ctx, nil); err != nil {
		t.Fatalf("VerifyScans: %v", err)
	}

	counts := d.ShardCounts()
	if counts.UnusableDataShardCount != 0 {
		t.Fatalf("expected 0 unusable shards, got %d", counts.UnusableDataShardCount)
	}

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

	progressChan := make(chan Progress, 10)
	go func() {
		for range progressChan {
		}
	}()

	if err := d.Repair(ctx, progressChan); err != nil {
		t.Fatalf("Repair: %v", err)
	}

	repaired, err := os.ReadFile(correctName)
	if err != nil {
		t.Fatalf("correct.dat should exist after repair: %v", err)
	}
	if !bytes.Equal(repaired, fileData) {
		t.Fatal("repaired file content does not match original")
	}

	if _, err := os.Stat(wrongName); !os.IsNotExist(err) {
		t.Fatal("wrong_name.dat should not exist after rename")
	}

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

func TestRenameMisnamedFile_CreatesDirectory(t *testing.T) {
	if !hasPar2Cmd() {
		t.Skip("par2 binary not found in PATH")
	}

	dir := t.TempDir()
	r := rand.New(rand.NewPCG(88, 88))
	fileData := make([]byte, 1024)
	for i := range fileData {
		fileData[i] = byte(r.Uint32())
	}

	// We want target to be nested: nested/dir/correct.dat
	nestedTarget := filepath.Join("nested", "dir", "correct.dat")
	correctName := filepath.Join(dir, nestedTarget)

	// Create the directory temporarily to write correctName, then we will recreate the archive
	if err := os.MkdirAll(filepath.Dir(correctName), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(correctName, fileData, 0644); err != nil {
		t.Fatal(err)
	}

	par2Path := filepath.Join(dir, "set.par2")
	// Run par2 c relative to dir
	cmd := exec.Command("par2", "c", "-s1024", "-c1", par2Path, correctName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("par2 create: %v\n%s", err, out)
	}

	// Now rename the source and remove the nested directory structure
	wrongName := filepath.Join(dir, "wrong_name.dat")
	if err := os.Rename(correctName, wrongName); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "nested")); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	d, err := NewDecoder(ctx, par2Path, DecoderOptions{Logger: slog.Default()})
	if err != nil {
		t.Fatalf("NewDecoder: %v", err)
	}
	defer func() { _ = d.Close() }()

	if err := d.AddCandidateFile("wrong_name.dat"); err != nil {
		t.Fatalf("AddCandidateFile: %v", err)
	}

	if err := d.VerifyScans(ctx, nil); err != nil {
		t.Fatalf("VerifyScans: %v", err)
	}

	progressChan := make(chan Progress, 10)
	go func() {
		for range progressChan {
		}
	}()

	if err := d.Repair(ctx, progressChan); err != nil {
		t.Fatalf("Repair: %v", err)
	}

	// Check if nested/dir/correct.dat exists and has correct content
	repaired, err := os.ReadFile(correctName)
	if err != nil {
		t.Fatalf("correctName should exist after rename: %v", err)
	}
	if !bytes.Equal(repaired, fileData) {
		t.Fatal("repaired file content mismatch")
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
		fileIntegrity: make(map[FileID]*fileIntegrityState),
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

// TestScanLastPartialBlock verifies that a file whose size is not a multiple of
// sliceByteCount emits a match event for the zero-padded final block.
func TestScanLastPartialBlock(t *testing.T) {
	const sliceSize = 8
	// 11 bytes: full shard at [0,8), partial shard at [8,11) padded to [8,16)
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

	tmp, err := os.CreateTemp(t.TempDir(), "partial")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tmp.Close() }()
	if _, err := tmp.Write(data); err != nil {
		t.Fatal(err)
	}

	paddedBlock := make([]byte, sliceSize)
	copy(paddedBlock, data[8:]) // 3 real bytes + 5 zero bytes
	crcVal := crc32.ChecksumIEEE(paddedBlock)
	md5Val := md5.Sum(paddedBlock)

	var fid FileID
	scanner := &blockScanner{
		d: &Decoder{sliceByteCount: sliceSize, logger: slog.Default()},
		lookupTable: newCRCLookupTable(map[uint32][]checksumLocation{
			crcVal: {{fileID: fid, shardIndex: 1, md5Hash: md5Val}},
		}),
		matchChan: make(chan matchEvent, 5),
	}

	if err := scanner.scanLastPartialBlock(tmp, fid, int64(len(data))); err != nil {
		t.Fatalf("scanLastPartialBlock: %v", err)
	}
	close(scanner.matchChan)

	var got []matchEvent
	for ev := range scanner.matchChan {
		got = append(got, ev)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 match event, got %d", len(got))
	}
	if got[0].shardIndex != 1 || got[0].offset != 8 {
		t.Errorf("match: shardIndex=%d offset=%d, want shardIndex=1 offset=8", got[0].shardIndex, got[0].offset)
	}
}

// TestScanLastPartialBlockAligned confirms no I/O occurs when the file size is
// exactly divisible by sliceByteCount (no partial block to check).
func TestScanLastPartialBlockAligned(t *testing.T) {
	scanner := &blockScanner{
		d:           &Decoder{sliceByteCount: 8, logger: slog.Default()},
		lookupTable: newCRCLookupTable(nil),
		matchChan:   make(chan matchEvent, 5),
	}
	// Passing nil for f is safe: the early-return triggers before any read.
	if err := scanner.scanLastPartialBlock(nil, FileID{}, 16); err != nil {
		t.Fatalf("expected no-op for aligned file, got: %v", err)
	}
	close(scanner.matchChan)
	if len(scanner.matchChan) != 0 {
		t.Error("expected no match events for exactly aligned file size")
	}
}

// TestScanCandidateFile confirms that scanCandidateFile emits a match event
// for a shard found in a registered candidate file (no par2 binary required).
func TestScanCandidateFile(t *testing.T) {
	const sliceSize = 8
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "candidate.dat"), data, 0644); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	shard0 := data[:sliceSize]
	crc0 := crc32.ChecksumIEEE(shard0)
	md5of0 := md5.Sum(shard0)

	var targetFileID, candidateID FileID
	targetFileID[0] = 0x01
	candidateID[0] = 0x02

	window, err := newCRC32Window(sliceSize)
	if err != nil {
		t.Fatal(err)
	}
	scanner := &blockScanner{
		d:      &Decoder{sliceByteCount: sliceSize, logger: slog.Default(), root: root},
		ctx:    context.Background(),
		window: window,
		sem:    make(chan struct{}, 4),
		lookupTable: newCRCLookupTable(map[uint32][]checksumLocation{
			crc0: {{fileID: targetFileID, shardIndex: 0, md5Hash: md5of0}},
		}),
		matchChan: make(chan matchEvent, 10),
	}

	if err := scanner.scanCandidateFile("candidate.dat", candidateID); err != nil {
		t.Fatalf("scanCandidateFile: %v", err)
	}
	close(scanner.matchChan)

	var found bool
	for ev := range scanner.matchChan {
		if ev.shardIndex == 0 && ev.offset == 0 && ev.sourceFileID == candidateID {
			found = true
		}
	}
	if !found {
		t.Error("expected shard 0 at offset 0 from candidateID — not found")
	}
}

// TestVerifySingleFileHash covers the three code paths in verifySingleFileHash:
// correct hash → Verified=true, wrong hash → HashMismatch=true, file missing → Missing=true.
//
// Note: this path is defensive. In normal flow the prescan catches healthy files
// and corrupt files fail isAllShardsConsecutive, so the integration suite rarely
// exercises this function.
func TestVerifySingleFileHash(t *testing.T) {
	dir := t.TempDir()
	content := []byte("test content for hash verification")
	const fname = "hashtest.dat"
	if err := os.WriteFile(filepath.Join(dir, fname), content, 0644); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := &Decoder{root: root, logger: slog.Default()}
	defer func() { _ = d.Close() }()

	actualMD5 := md5.Sum(content)

	t.Run("correct_hash_sets_verified", func(t *testing.T) {
		state := &fileIntegrityState{}
		d.verifySingleFileHash(context.Background(), FileDescPacket{Filename: fname, Hash: actualMD5}, state)
		if !state.Verified {
			t.Error("expected Verified=true for correct hash")
		}
		if state.HashMismatch {
			t.Error("expected HashMismatch=false for correct hash")
		}
	})

	t.Run("wrong_hash_sets_hash_mismatch", func(t *testing.T) {
		state := &fileIntegrityState{}
		d.verifySingleFileHash(context.Background(), FileDescPacket{Filename: fname, Hash: [16]byte{0xFF}}, state)
		if !state.HashMismatch {
			t.Error("expected HashMismatch=true for wrong hash")
		}
		if state.Verified {
			t.Error("expected Verified=false for wrong hash")
		}
	})

	t.Run("missing_file_sets_missing", func(t *testing.T) {
		state := &fileIntegrityState{}
		d.verifySingleFileHash(context.Background(), FileDescPacket{Filename: "no_such_file.dat", Hash: actualMD5}, state)
		if !state.Missing {
			t.Error("expected Missing=true for inaccessible file")
		}
	})
}

// TestDetectRenameCandidate covers the failure paths and happy path of
// detectRenameCandidate. Must be called with d.mu held; the helper wrapper
// below enforces this uniformly so the lock/unlock pairs balance on every path.
func TestDetectRenameCandidate(t *testing.T) {
	dir := t.TempDir()
	content := []byte("rename candidate file content")
	const candidateName = "candidate.dat"
	if err := os.WriteFile(filepath.Join(dir, candidateName), content, 0644); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}

	var targetFileID, candidateID FileID
	targetFileID[0] = 0x01
	candidateID[0] = 0x02

	contentMD5 := md5.Sum(content)
	const sliceSize = len("rename candidate file content") // single shard

	newDecoder := func() *Decoder {
		return &Decoder{
			root:           root,
			logger:         slog.Default(),
			sliceByteCount: sliceSize,
			candidateFiles: map[string]FileID{candidateName: candidateID},
			candidateByID:  map[FileID]string{candidateID: candidateName},
		}
	}
	// call holds d.mu for the duration, balancing the internal Unlock/Lock on
	// paths that reach I/O and the no-op balance on early-exit paths.
	call := func(d *Decoder, fd FileDescPacket, state *fileIntegrityState) string {
		d.mu.Lock()
		result := d.detectRenameCandidate(context.Background(), fd, state)
		d.mu.Unlock()
		return result
	}

	t.Run("first_shard_missing_returns_empty", func(t *testing.T) {
		state := &fileIntegrityState{ShardLocations: []shardLocation{{Offset: -1}}}
		if got := call(newDecoder(), FileDescPacket{FileID: targetFileID, Filename: "target.dat"}, state); got != "" {
			t.Errorf("want empty, got %q", got)
		}
	})

	t.Run("shard_from_target_itself_returns_empty", func(t *testing.T) {
		state := &fileIntegrityState{ShardLocations: []shardLocation{{FileID: targetFileID, Offset: 0}}}
		if got := call(newDecoder(), FileDescPacket{FileID: targetFileID, Filename: "target.dat"}, state); got != "" {
			t.Errorf("want empty, got %q", got)
		}
	})

	t.Run("unknown_candidate_id_returns_empty", func(t *testing.T) {
		var unknownID FileID
		unknownID[0] = 0x99
		state := &fileIntegrityState{ShardLocations: []shardLocation{{FileID: unknownID, Offset: 0}}}
		if got := call(newDecoder(), FileDescPacket{FileID: targetFileID, Filename: "target.dat"}, state); got != "" {
			t.Errorf("want empty, got %q", got)
		}
	})

	t.Run("same_filename_as_candidate_returns_empty", func(t *testing.T) {
		state := &fileIntegrityState{ShardLocations: []shardLocation{{FileID: candidateID, Offset: 0}}}
		// fd.Filename == candidateName — same file, not a rename.
		if got := call(newDecoder(), FileDescPacket{FileID: targetFileID, Filename: candidateName, Hash: contentMD5}, state); got != "" {
			t.Errorf("want empty, got %q", got)
		}
	})

	t.Run("md5_mismatch_returns_empty", func(t *testing.T) {
		state := &fileIntegrityState{ShardLocations: []shardLocation{{FileID: candidateID, Offset: 0}}}
		if got := call(newDecoder(), FileDescPacket{FileID: targetFileID, Filename: "target.dat", Hash: [16]byte{0xFF}}, state); got != "" {
			t.Errorf("want empty, got %q", got)
		}
	})

	t.Run("happy_path_returns_candidate_path", func(t *testing.T) {
		state := &fileIntegrityState{ShardLocations: []shardLocation{{FileID: candidateID, Offset: 0}}}
		if got := call(newDecoder(), FileDescPacket{FileID: targetFileID, Filename: "target.dat", Hash: contentMD5}, state); got != candidateName {
			t.Errorf("want %q, got %q", candidateName, got)
		}
	})
}

func TestVerificationReporting(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.dat"), []byte("okfilecontent"), 0644); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}

	d := &Decoder{
		root:          root,
		logger:        logger,
		fileChecksums: make(map[FileID]*IFSCPacket),
		parityShards:  make(map[uint16][]byte),
		fileIntegrity: make(map[FileID]*fileIntegrityState),
	}
	defer func() { _ = d.Close() }()

	idOK := FileID{0x01}
	idMissing := FileID{0x02}
	idMismatch := FileID{0x03}
	idRename := FileID{0x04}
	idDamaged := FileID{0x05}

	d.protectedFiles = []FileDescPacket{
		{FileID: idOK, Filename: "ok.dat", ByteCount: 13},
		{FileID: idMissing, Filename: "missing.dat", ByteCount: 10},
		{FileID: idMismatch, Filename: "mismatch.dat", ByteCount: 10},
		{FileID: idRename, Filename: "rename_dest.dat", ByteCount: 10},
		{FileID: idDamaged, Filename: "damaged.dat", ByteCount: 10},
	}

	d.fileIntegrity[idOK] = &fileIntegrityState{
		ShardLocations: []shardLocation{{FileID: idOK, Offset: 0}},
	}
	d.fileIntegrity[idMissing] = &fileIntegrityState{
		Missing:        true,
		ShardLocations: []shardLocation{{FileID: idMissing, Offset: -1}},
	}
	d.fileIntegrity[idMismatch] = &fileIntegrityState{
		SizeMismatch:   true,
		ShardLocations: []shardLocation{{FileID: idMismatch, Offset: -1}},
	}
	d.fileIntegrity[idRename] = &fileIntegrityState{
		RenameSource:   "rename_src.dat",
		ShardLocations: []shardLocation{{FileID: idRename, Offset: -1}},
	}
	d.fileIntegrity[idDamaged] = &fileIntegrityState{
		HashMismatch:   true,
		ShardLocations: []shardLocation{{FileID: idDamaged, Offset: -1}},
	}

	d.logVerificationReport(context.Background(), ShardCounts{
		UnusableDataShardCount: 2,
		RenamesNeeded:          1,
	})

	logOutput := buf.String()
	t.Log(logOutput)

	expectedLogs := []string{
		"File status: OK",
		"File status: SIZE MISMATCH",
		"File status: DAMAGED",
		"File status: MISNAMED",
		"Verification summary",
		"totalFiles=5",
		"ok=1",
		"missing=1",
		"damaged=2",
		"misnamed=1",
	}

	for _, expected := range expectedLogs {
		if !strings.Contains(logOutput, expected) {
			t.Errorf("expected log output to contain %q", expected)
		}
	}
}

func TestRenameMisnamedFiles_ErrorPaths(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "subdir"), []byte("not a dir"), 0644); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}

	d := &Decoder{
		root:          root,
		logger:        slog.Default(),
		fileChecksums: make(map[FileID]*IFSCPacket),
		parityShards:  make(map[uint16][]byte),
		fileIntegrity: make(map[FileID]*fileIntegrityState),
	}
	defer func() { _ = d.Close() }()

	idMkdirFail := FileID{0x01}
	idRenameFail := FileID{0x02}

	d.protectedFiles = []FileDescPacket{
		{FileID: idMkdirFail, Filename: "subdir/dest.dat", ByteCount: 10},
		{FileID: idRenameFail, Filename: "dest2.dat", ByteCount: 10},
	}

	d.fileIntegrity[idMkdirFail] = &fileIntegrityState{
		RenameSource:   "source1.dat",
		ShardLocations: []shardLocation{{Offset: -1}},
	}
	d.fileIntegrity[idRenameFail] = &fileIntegrityState{
		RenameSource:   "nonexistent_source.dat",
		ShardLocations: []shardLocation{{Offset: -1}},
	}

	renamed := d.renameMisnamedFiles(context.Background())
	if renamed != 0 {
		t.Errorf("expected 0 files renamed, got %d", renamed)
	}

	state1 := d.fileIntegrity[idMkdirFail]
	if state1.RenameSource != "" || !state1.HashMismatch {
		t.Errorf("expected fallback to repair for MkdirAll failure, got RenameSource=%q HashMismatch=%v", state1.RenameSource, state1.HashMismatch)
	}

	state2 := d.fileIntegrity[idRenameFail]
	if state2.RenameSource != "" || !state2.HashMismatch {
		t.Errorf("expected fallback to repair for Rename failure, got RenameSource=%q HashMismatch=%v", state2.RenameSource, state2.HashMismatch)
	}
}

func TestScanFileChunks_ErrorPropagation(t *testing.T) {
	dir := t.TempDir()
	fname := "testfile.dat"
	if err := os.WriteFile(filepath.Join(dir, fname), make([]byte, 100), 0644); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()

	f, err := root.Open(fname)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	scanner := &blockScanner{
		d:           &Decoder{sliceByteCount: 8, logger: slog.Default(), root: root},
		ctx:         context.Background(),
		sem:         make(chan struct{}, 1),
		lookupTable: newCRCLookupTable(nil),
	}

	err = scanner.scanFileChunks(f, FileID{}, fname, 100)
	if err == nil {
		t.Fatal("expected error from scanning closed file descriptor, got nil")
	}
}
