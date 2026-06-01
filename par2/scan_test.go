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
	"testing"
)

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
