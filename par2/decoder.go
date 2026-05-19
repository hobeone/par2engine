package par2

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hobeone/par2engine/rs"
)

// Progress represents a progress update sent during verification or repair.
type Progress struct {
	Phase   string  // "verifying" or "repairing"
	Current int64   // bytes or blocks completed
	Total   int64   // total bytes or blocks
	Percent float64 // progress percentage
}

// ShardLocation describes the exact location of a matched shard block on disk.
type ShardLocation struct {
	FileID FileID // the FileID of the physical file on disk where the block was found
	Offset int64  // byte offset in the file on disk. -1 if missing.
}

// FileIntegrityState tracks which blocks are healthy and where they are located on disk.
type FileIntegrityState struct {
	FileID         FileID
	Filename       string
	Missing        bool
	SizeMismatch   bool
	HashMismatch   bool
	ShardLocations []ShardLocation // maps expected shardIndex -> where it is actually located
}

// ShardCounts captures statistical shard availability status.
type ShardCounts struct {
	UsableDataShardCount     int
	UnusableDataShardCount   int
	UsableParityShardCount   int
	UnusableParityShardCount int
}

func (sc ShardCounts) RepairNeeded() bool {
	return sc.UnusableDataShardCount > 0
}

func (sc ShardCounts) RepairPossible() bool {
	return sc.UsableParityShardCount >= sc.UnusableDataShardCount
}

// Decoder is the core PAR2 verification and repair engine.
type Decoder struct {
	numGoroutines int
	memoryLimit   int64
	logger        *slog.Logger

	root *os.Root // sandboxed target folder directory root (Go 1.24+)
	absRootDir string // absolute resolved target folder directory path

	sliceByteCount int
	recoverySetID  [16]byte
	recoveryFiles  []FileDescPacket
	fileChecksums  map[FileID]*IFSCPacket
	parityShards   map[uint16][]byte // exponent -> parity bytes loaded from par2 files

	fileIntegrity map[FileID]*FileIntegrityState
	mu            sync.Mutex // protects shared state updates
}

type checksumLocation struct {
	fileID     FileID
	shardIndex int
	md5Hash    [16]byte
}

type matchEvent struct {
	targetFileID FileID // the file that EXPECTS this block
	shardIndex   int
	sourceFileID FileID // the file where we FOUND this block
	offset       int64
}

// NewDecoder opens a sandboxed target directory relative to the index par2 file,
// parses the index par2 manifest, and returns a Decoder.
func NewDecoder(ctx context.Context, par2Path string, numGoroutines int, memLimit int64, logger *slog.Logger) (*Decoder, error) {
	if numGoroutines <= 0 {
		numGoroutines = rs.DefaultNumGoroutines()
	}
	if memLimit <= 0 {
		memLimit = 16 * 1024 * 1024 // 16MB default memory limit
	}
	if logger == nil {
		logger = slog.Default()
	}

	dir := filepath.Dir(par2Path)
	indexFilename := filepath.Base(par2Path)

	absDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve canonical path: %w", err)
	}
	root, err := os.OpenRoot(absDir)
	if err != nil {
		return nil, fmt.Errorf("failed to sandbox target directory: %w", err)
	}

	d := &Decoder{
		numGoroutines: numGoroutines,
		memoryLimit:   memLimit,
		logger:        logger,
		root:          root,
		absRootDir:    absDir,
		fileChecksums: make(map[FileID]*IFSCPacket),
		parityShards:  make(map[uint16][]byte),
		fileIntegrity: make(map[FileID]*FileIntegrityState),
	}

	err = d.loadIndexFile(ctx, indexFilename)
	if err != nil {
		root.Close()
		return nil, err
	}

	err = d.loadVolumeFiles(ctx, indexFilename)
	if err != nil {
		root.Close()
		return nil, err
	}

	return d, nil
}

func (d *Decoder) Close() error {
	if d.root != nil {
		return d.root.Close()
	}
	return nil
}

func (d *Decoder) loadIndexFile(ctx context.Context, indexFilename string) error {
	d.logger.InfoContext(ctx, "Loading index PAR2 file", "file", indexFilename)

	// Read file relative to sandbox root
	f, err := d.root.Open(indexFilename)
	if err != nil {
		return fmt.Errorf("failed to open index par2 file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	for r.Len() > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		h, err := ReadHeader(r)
		if err != nil {
			return fmt.Errorf("failed to read packet header: %w", err)
		}

		bodyLen := int(h.Length - 64)
		body := make([]byte, bodyLen)
		_, err = r.Read(body)
		if err != nil {
			return err
		}

		if ComputePacketHash(h.RecoverySetID, h.Type, body) != h.Hash {
			return errors.New("corrupt index packet hash mismatch")
		}

		if d.recoverySetID == [16]byte{} {
			d.recoverySetID = h.RecoverySetID
		} else if d.recoverySetID != h.RecoverySetID {
			d.logger.Warn("skipping packet with mismatching set ID")
			continue
		}

		switch h.Type {
		case MainPacketType:
			p, err := ParseMainPacket(body)
			if err != nil {
				return err
			}
			d.sliceByteCount = p.SliceByteCount
			d.logger.InfoContext(ctx, "Parsed SliceByteCount", "size", p.SliceByteCount)

		case FileDescPacketType:
			p, err := ParseFileDescPacket(body)
			if err != nil {
				return err
			}
			d.recoveryFiles = append(d.recoveryFiles, *p)
			d.logger.InfoContext(ctx, "Parsed expected recovery file", "name", p.Filename, "size", p.ByteCount)

		case IFSCPacketType:
			p, err := ParseIFSCPacket(body)
			if err != nil {
				return err
			}
			d.fileChecksums[p.FileID] = p

		case RecoveryPacketType:
			p, err := ParseRecoveryPacket(body)
			if err != nil {
				return err
			}
			d.parityShards[p.Exponent] = p.Data
		}
	}

	// PAR2 spec strictly requires recovery files to be sorted alphabetically by FileID
	sort.Slice(d.recoveryFiles, func(i, j int) bool {
		return FileIDLess(d.recoveryFiles[i].FileID, d.recoveryFiles[j].FileID)
	})

	return nil
}

// ShardCounts calculates shard availability based on the current integrity scan.
func (d *Decoder) ShardCounts() ShardCounts {
	d.mu.Lock()
	defer d.mu.Unlock()

	usableData := 0
	unusableData := 0
	for _, state := range d.fileIntegrity {
		for _, loc := range state.ShardLocations {
			if loc.Offset == -1 {
				unusableData++
			} else {
				usableData++
			}
		}
	}

	usableParity := len(d.parityShards)
	return ShardCounts{
		UsableDataShardCount:     usableData,
		UnusableDataShardCount:   unusableData,
		UsableParityShardCount:   usableParity,
		UnusableParityShardCount: 0,
	}
}

// VerifyScans parallelizes file scanning. Exposes a throttled progress channel.
func (d *Decoder) VerifyScans(ctx context.Context, progressChan chan<- Progress) error {
	d.mu.Lock()
	d.fileIntegrity = make(map[FileID]*FileIntegrityState)
	for _, f := range d.recoveryFiles {
		shards := (f.ByteCount + d.sliceByteCount - 1) / d.sliceByteCount
		locs := make([]ShardLocation, shards)
		for i := range locs {
			locs[i] = ShardLocation{Offset: -1}
		}
		d.fileIntegrity[f.FileID] = &FileIntegrityState{
			FileID:         f.FileID,
			Filename:       f.Filename,
			ShardLocations: locs,
		}
	}
	d.mu.Unlock()

	window := newCRC32Window(d.sliceByteCount)

	// Build expected checksum map
	checksumMap := make(map[uint32][]checksumLocation)
	for fID, ifsc := range d.fileChecksums {
		for shardIdx, pair := range ifsc.ChecksumPairs {
			crcVal := binary.LittleEndian.Uint32(pair.CRC32[:])
			checksumMap[crcVal] = append(checksumMap[crcVal], checksumLocation{
				fileID:     fID,
				shardIndex: shardIdx,
				md5Hash:    pair.MD5,
			})
		}
	}

	matchChan := make(chan matchEvent, 100)
	var scanWg sync.WaitGroup

	var scanErr error
	var scanErrMu sync.Mutex
	setScanErr := func(err error) {
		scanErrMu.Lock()
		defer scanErrMu.Unlock()
		if scanErr == nil {
			scanErr = err
		}
	}

	// 1. Sequential Match Collector
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for match := range matchChan {
			d.mu.Lock()
			state := d.fileIntegrity[match.targetFileID]
			if state.ShardLocations[match.shardIndex].Offset == -1 {
				state.ShardLocations[match.shardIndex] = ShardLocation{
					FileID: match.sourceFileID,
					Offset: match.offset,
				}
			}
			d.mu.Unlock()
		}
	}()

	// 2. Scan protected files in parallel using a shared program-wide semaphore
	sem := make(chan struct{}, d.numGoroutines)
	for _, fDesc := range d.recoveryFiles {
		if ctx.Err() != nil {
			break
		}

		scanWg.Add(1)
		go func(fd FileDescPacket) {
			defer scanWg.Done()

			err := d.scanFile(ctx, fd, window, sem, checksumMap, matchChan)
			if err != nil {
				d.logger.ErrorContext(ctx, "failed to scan file", "file", fd.Filename, "err", err)
				setScanErr(err)
			}
		}(fDesc)
	}

	scanWg.Wait()
	close(matchChan)
	collectorWg.Wait()

	if scanErr != nil {
		return scanErr
	}

	// Post-scan global hash check
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, fd := range d.recoveryFiles {
		state := d.fileIntegrity[fd.FileID]
		if state.Missing || state.SizeMismatch {
			continue
		}
		// Verify overall file hash if all shards are matched at expected consecutive offsets
		allConsecutive := true
		for idx, loc := range state.ShardLocations {
			expected := int64(idx * d.sliceByteCount)
			if loc.Offset != expected || loc.FileID != fd.FileID {
				allConsecutive = false
				break
			}
		}

		if allConsecutive {
			// Standard full file MD5 check
			f, err := d.root.Open(fd.Filename)
			if err != nil {
				state.Missing = true
				continue
			}
			hasher := md5.New()
			_, _ = io.Copy(hasher, f)
			f.Close()
			var fileHash [16]byte
			copy(fileHash[:], hasher.Sum(nil))
			d.logger.InfoContext(ctx, "MD5 verification", "file", fd.Filename, "got", fmt.Sprintf("%x", fileHash), "want", fmt.Sprintf("%x", fd.Hash))
			if fileHash != fd.Hash {
				state.HashMismatch = true
			}
		} else {
			state.HashMismatch = true
		}
	}

	return ctx.Err()
}

func (d *Decoder) scanFile(ctx context.Context, fd FileDescPacket, window *crc32Window, sem chan struct{}, checksumMap map[uint32][]checksumLocation, matchChan chan<- matchEvent) error {
	f, err := d.root.Open(fd.Filename)
	if os.IsNotExist(err) {
		d.mu.Lock()
		d.fileIntegrity[fd.FileID].Missing = true
		d.mu.Unlock()
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return err
	}

	d.mu.Lock()
	state := d.fileIntegrity[fd.FileID]
	if stat.Size() != int64(fd.ByteCount) {
		state.SizeMismatch = true
	}
	d.mu.Unlock()

	fileSize := stat.Size()
	if fileSize == 0 {
		return nil
	}

	// Chunk size: 32MB for internal parallel scanning of single large file
	const scanChunkSize = 32 * 1024 * 1024
	var chunkWg sync.WaitGroup

	numChunks := (fileSize + scanChunkSize - 1) / scanChunkSize
	for i := int64(0); i < numChunks; i++ {
		if ctx.Err() != nil {
			break
		}

		chunkWg.Add(1)
		go func(chunkIdx int64) {
			defer chunkWg.Done()

			// Throttle concurrency at the chunk level to respect memory limits
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			start := chunkIdx * scanChunkSize
			end := start + scanChunkSize + int64(d.sliceByteCount) - 1
			if end > fileSize {
				end = fileSize
			}

			d.scanChunk(ctx, f, fd.FileID, window, start, end, checksumMap, matchChan)
		}(i)
	}

	chunkWg.Wait()

	// Natively verify the last partial block if the file size is not a multiple of sliceByteCount
	shards := (fd.ByteCount + d.sliceByteCount - 1) / d.sliceByteCount
	if fd.ByteCount%d.sliceByteCount != 0 {
		lastBlockStart := int64((shards - 1) * d.sliceByteCount)
		lastBlockLen := int64(fd.ByteCount) - lastBlockStart

		partialData := make([]byte, lastBlockLen)
		_, err = f.ReadAt(partialData, lastBlockStart)
		if err != nil && err != io.EOF {
			return err
		}

		// Zero-padded to full block size
		paddedBlock := make([]byte, d.sliceByteCount)
		copy(paddedBlock, partialData)

		crcVal := crc32.ChecksumIEEE(paddedBlock)
		if locations, found := checksumMap[crcVal]; found {
			blockHash := md5.Sum(paddedBlock)
			for _, loc := range locations {
				if loc.md5Hash == blockHash {
					matchChan <- matchEvent{
						targetFileID: loc.fileID,
						shardIndex:   loc.shardIndex,
						sourceFileID: fd.FileID,
						offset:       lastBlockStart,
					}
				}
			}
		}
	}

	return nil
}

func (d *Decoder) scanChunk(ctx context.Context, f *os.File, sourceFileID FileID, window *crc32Window, start, end int64, checksumMap map[uint32][]checksumLocation, matchChan chan<- matchEvent) {
	bufferSize := end - start
	if bufferSize < int64(d.sliceByteCount) {
		return
	}
	data := make([]byte, bufferSize)
	_, err := f.ReadAt(data, start)
	if err != nil && err != io.EOF {
		return
	}

	var crcSlice uint32
	justMissed := false

	for j := 0; j <= len(data)-d.sliceByteCount; {
		if ctx.Err() != nil {
			return
		}

		slice := data[j : j+d.sliceByteCount]
		if justMissed {
			crcSlice = window.update(crcSlice, data[j-1], slice[len(slice)-1])
		} else {
			crcSlice = crc32.ChecksumIEEE(slice)
		}

		locations, found := checksumMap[crcSlice]
		if !found {
			j++
			justMissed = true
			continue
		}

		blockHash := md5.Sum(slice)
		for _, loc := range locations {
			if loc.md5Hash == blockHash {
				matchChan <- matchEvent{
					targetFileID: loc.fileID,
					shardIndex:   loc.shardIndex,
					sourceFileID: sourceFileID,
					offset:       start + int64(j),
				}
			}
		}

		j += d.sliceByteCount
		justMissed = false
	}
}

// Repair performs pipelined, strict memory-limited reconstruction of missing shards.
func (d *Decoder) Repair(ctx context.Context, progressChan chan<- Progress) error {
	counts := d.ShardCounts()
	if !counts.RepairNeeded() {
		d.logger.InfoContext(ctx, "No repair needed. All files are healthy.")
		return nil
	}
	if !counts.RepairPossible() {
		return fmt.Errorf("repair not possible: need %d parity shards, have %d usable",
			counts.UnusableDataShardCount, counts.UsableParityShardCount)
	}

	d.logger.InfoContext(ctx, "Starting pipelined repair...", "missing", counts.UnusableDataShardCount)

	// Total data shards in PAR2 set
	totalDataShards := 0
	for _, f := range d.recoveryFiles {
		totalDataShards += len(d.fileIntegrity[f.FileID].ShardLocations)
	}

	// Calculate the maximum exponent to determine the Vandermonde row dimensions
	maxExp := 0
	for exp := range d.parityShards {
		if int(exp) > maxExp {
			maxExp = int(exp)
		}
	}
	totalParityShards := maxExp + 1

	// Prepare arrays of present data shards and chosen parity shards aligned to exponents.
	dataBuffers := make([][]byte, totalDataShards)
	parityBuffers := make([][]byte, totalParityShards)

	// Establish safe streaming chunksize based on memory limit (default 16MB).
	// memoryLimit = chunksize * (totalDataShards + usableParityUsed)
	// chunksize must be a multiple of 16 bytes for Galois aligned performance.
	chunkSize := d.memoryLimit / int64(totalDataShards+counts.UnusableDataShardCount)
	if chunkSize > int64(d.sliceByteCount) {
		chunkSize = int64(d.sliceByteCount)
	}
	chunkSize = (chunkSize / 16) * 16
	if chunkSize < 16 {
		chunkSize = 16
	}

	d.logger.InfoContext(ctx, "Configured memory-limited streaming", "chunkSize", chunkSize, "sliceByteCount", d.sliceByteCount)

	// Allocate streaming buffers
	for i := range dataBuffers {
		dataBuffers[i] = make([]byte, chunkSize)
	}
	for i := range parityBuffers {
		parityBuffers[i] = make([]byte, chunkSize)
	}

	// Flatten all file shard locations into a sequential list
	type flattenedLocation struct {
		targetFileID   FileID
		targetFilename string
		shardIndex     int
		sourceFileID   FileID
		sourceFilename string
		diskOffset     int64 // -1 if missing
	}
	
	fileIDToFilename := make(map[FileID]string)
	for _, f := range d.recoveryFiles {
		fileIDToFilename[f.FileID] = f.Filename
	}

	flatLocs := make([]flattenedLocation, totalDataShards)
	k := 0
	for _, f := range d.recoveryFiles {
		state := d.fileIntegrity[f.FileID]
		for shardIdx, loc := range state.ShardLocations {
			var srcFilename string
			if loc.Offset != -1 {
				srcFilename = fileIDToFilename[loc.FileID]
			}
			flatLocs[k] = flattenedLocation{
				targetFileID:   f.FileID,
				targetFilename: f.Filename,
				shardIndex:     shardIdx,
				sourceFileID:   loc.FileID,
				sourceFilename: srcFilename,
				diskOffset:     loc.Offset,
			}
			k++
		}
	}


	// Pre-determine which files need write access for repair
	needsWrite := make(map[string]bool)
	for _, f := range d.recoveryFiles {
		state := d.fileIntegrity[f.FileID]
		if state.Missing || state.SizeMismatch || state.HashMismatch {
			needsWrite[f.Filename] = true
			continue
		}
		for shardIdx, loc := range state.ShardLocations {
			expectedOffset := int64(shardIdx * d.sliceByteCount)
			if loc.Offset != expectedOffset || loc.FileID != f.FileID {
				needsWrite[f.Filename] = true
				break
			}
		}
	}

	// Reopen all files using os.Root (reopen handles or keep them in map to avoid filesystem overhead)
	openFiles := make(map[string]*os.File)
	getFile := func(name string) (*os.File, error) {
		if f, ok := openFiles[name]; ok {
			return f, nil
		}
		var f *os.File
		var err error
		if needsWrite[name] {
			f, err = d.root.OpenFile(name, os.O_RDWR|os.O_CREATE, 0644)
		} else {
			f, err = d.root.Open(name)
		}
		if err != nil {
			return nil, err
		}
		openFiles[name] = f
		return f, nil
	}
	defer func() {
		for _, f := range openFiles {
			f.Close()
		}
	}()

	coder, err := rs.NewCoderPAR2Vandermonde(totalDataShards, totalParityShards)
	if err != nil {
		return err
	}

	// Stream data chunk by chunk
	numChunks := (int64(d.sliceByteCount) + chunkSize - 1) / chunkSize
	for chunkIdx := int64(0); chunkIdx < numChunks; chunkIdx++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		currChunkSize := chunkSize
		if chunkIdx == numChunks-1 {
			currChunkSize = int64(d.sliceByteCount) - (chunkIdx * chunkSize)
		}

		// 1. READER PIPELINE: Read input buffers from disk
		var activeDataShards [][]byte

		// Read present data shards relative to their offset on disk
		for i, fl := range flatLocs {
			if fl.diskOffset != -1 {
				f, err := getFile(fl.sourceFilename)
				if err != nil {
					return err
				}
				offset := fl.diskOffset + (chunkIdx * chunkSize)
				n, err := f.ReadAt(dataBuffers[i][:currChunkSize], offset)
				if err != nil && err != io.EOF {
					return err
				}
				// Zero out the remaining padded slice space past EOF as strictly required by the PAR2 spec!
				if n < int(currChunkSize) {
					clear(dataBuffers[i][n:currChunkSize])
				}
				activeDataShards = append(activeDataShards, dataBuffers[i][:currChunkSize])
			} else {
				activeDataShards = append(activeDataShards, nil) // nil marks missing
			}
		}

		// Read parity shards strictly aligned to their exponent matrix row slots
		activeParityShards := make([][]byte, totalParityShards)
		for exp, parityBytes := range d.parityShards {
			offset := chunkIdx * chunkSize
			copy(parityBuffers[exp][:currChunkSize], parityBytes[offset:offset+currChunkSize])
			activeParityShards[exp] = parityBuffers[exp][:currChunkSize]
		}

		// 2. PROCESSOR PIPELINE: Reconstruct missing chunks concurrently
		err = coder.Reconstruct(ctx, activeDataShards, activeParityShards, d.numGoroutines)
		if err != nil {
			return err
		}

		// 3. WRITER PIPELINE: Write reconstructed chunks back to disk
		for i, fl := range flatLocs {
			expectedOffset := int64(fl.shardIndex * d.sliceByteCount)
			needsCopyOrRep := fl.diskOffset == -1 || fl.sourceFileID != fl.targetFileID || fl.diskOffset != expectedOffset

			if needsCopyOrRep {
				f, err := getFile(fl.targetFilename)
				if err != nil {
					return err
				}
				offset := expectedOffset + (chunkIdx * chunkSize)

				var dataToWrite []byte
				if fl.diskOffset == -1 {
					dataToWrite = activeDataShards[i]
				} else {
					dataToWrite = dataBuffers[i][:currChunkSize]
				}

				_, err = f.WriteAt(dataToWrite, offset)
				if err != nil {
					return err
				}
			}
		}

		// Report progress throttled
		if progressChan != nil {
			progressChan <- Progress{
				Phase:   "repairing",
				Current: chunkIdx + 1,
				Total:   numChunks,
				Percent: float64(chunkIdx+1) / float64(numChunks) * 100,
			}
		}
	}

	// Ensure repaired files are truncated to their exact expected byte counts
	for _, fd := range d.recoveryFiles {
		if needsWrite[fd.Filename] { // only truncate if we actually wrote to it!
			state := d.fileIntegrity[fd.FileID]
			if state.Missing || state.SizeMismatch || state.HashMismatch {
				f, err := getFile(fd.Filename)
				if err != nil {
					return err
				}
				err = f.Truncate(int64(fd.ByteCount))
				if err != nil {
					return err
				}
			}
		}
	}

	d.logger.InfoContext(ctx, "Repair completed successfully!")
	return nil
}

func (d *Decoder) loadVolumeFiles(ctx context.Context, indexFilename string) error {
	prefix := strings.TrimSuffix(indexFilename, ".par2")

	entries, err := os.ReadDir(d.absRootDir)
	if err != nil {
		return fmt.Errorf("failed to read sandboxed directory: %w", err)
	}

	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		name := entry.Name()
		if name == indexFilename {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".par2") {
			continue
		}
		if !strings.HasPrefix(name, prefix) {
			continue
		}

		err = d.loadSingleVolumeFile(ctx, name)
		if err != nil {
			d.logger.WarnContext(ctx, "failed to load recovery volume file (skipping)", "file", name, "err", err)
		}
	}

	return nil
}

func (d *Decoder) loadSingleVolumeFile(ctx context.Context, filename string) error {
	d.logger.InfoContext(ctx, "Loading recovery volume file", "file", filename)
	f, err := d.root.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)
	for r.Len() > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		h, err := ReadHeader(r)
		if err != nil {
			return err
		}

		bodyLen := int(h.Length - 64)
		body := make([]byte, bodyLen)
		_, err = r.Read(body)
		if err != nil {
			return err
		}

		if ComputePacketHash(h.RecoverySetID, h.Type, body) != h.Hash {
			return errors.New("corrupt volume packet hash mismatch")
		}

		if h.RecoverySetID != d.recoverySetID {
			d.logger.Warn("skipping volume packet with mismatching set ID")
			continue
		}

		switch h.Type {
		case RecoveryPacketType:
			p, err := ParseRecoveryPacket(body)
			if err != nil {
				return err
			}
			d.mu.Lock()
			d.parityShards[p.Exponent] = p.Data
			d.mu.Unlock()
		}
	}

	return nil
}
