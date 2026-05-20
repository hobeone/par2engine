package par2

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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

// BlocksNeeded returns the number of additional recovery blocks required
// to repair the set. Returns 0 when repair is not needed or is already possible.
func (sc ShardCounts) BlocksNeeded() int {
	deficit := sc.UnusableDataShardCount - sc.UsableParityShardCount
	if deficit < 0 {
		return 0
	}
	return deficit
}

// Decoder is the core PAR2 verification and repair engine.
type Decoder struct {
	numGoroutines int
	memoryLimit   int64
	maxFileSize   int64
	maxPacketSize int64
	logger        *slog.Logger

	root *os.Root // sandboxed target folder directory root (Go 1.24+)
	absRootDir string // absolute resolved target folder directory path

	sliceByteCount int
	recoverySetID  [16]byte
	protectedFiles  []FileDescPacket
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
func NewDecoder(ctx context.Context, par2Path string, numGoroutines int, memLimit int64, maxFileSize int64, maxPacketSize int64, logger *slog.Logger) (*Decoder, error) {
	if numGoroutines <= 0 {
		numGoroutines = rs.DefaultNumGoroutines()
	}
	if memLimit <= 0 {
		memLimit = 16 * 1024 * 1024 // 16MB default memory limit
	}
	if maxFileSize <= 0 {
		maxFileSize = 100 * 1024 * 1024 // 100MB default index file size limit
	}
	if maxPacketSize <= 0 {
		maxPacketSize = 128 * 1024 * 1024 // 128MB default packet body limit
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
		maxFileSize:   maxFileSize,
		maxPacketSize: maxPacketSize,
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

	// Reject PAR2 files exceeding maximum allowed size to prevent memory exhaustion DoS.
	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat index file: %w", err)
	}
	if stat.Size() > d.maxFileSize {
		return fmt.Errorf("index PAR2 file %s exceeds maximum allowed size (%d bytes > %d byte limit)", indexFilename, stat.Size(), d.maxFileSize)
	}

	// Use a loop to stream packet parsing without loading the whole file into memory.
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		h, err := ReadHeader(f)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read packet header: %w", err)
		}

		bodyLen := int64(h.Length - 64)
		if bodyLen < 0 || bodyLen > d.maxPacketSize {
			return errors.New("packet body exceeds safe engine limits")
		}
		body := make([]byte, bodyLen)
		_, err = io.ReadFull(f, body)
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
			d.protectedFiles = append(d.protectedFiles, *p)
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
			if _, exists := d.parityShards[p.Exponent]; exists {
				d.logger.WarnContext(ctx, "duplicate recovery packet exponent, skipping", "exponent", p.Exponent)
			} else {
				d.parityShards[p.Exponent] = p.Data
			}
		}
	}

	// PAR2 spec strictly requires protected files to be sorted alphabetically by FileID
	slices.SortFunc(d.protectedFiles, func(a, b FileDescPacket) int {
		if FileIDLess(a.FileID, b.FileID) {
			return -1
		}
		if FileIDLess(b.FileID, a.FileID) {
			return 1
		}
		return 0
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

// VerifyScans parallelizes file scanning to check integrity of all protected files.
func (d *Decoder) VerifyScans(ctx context.Context) error {
	d.mu.Lock()
	d.fileIntegrity = make(map[FileID]*FileIntegrityState)
	totalShards := 0
	for _, f := range d.protectedFiles {
		if d.sliceByteCount == 0 {
			d.mu.Unlock()
			return errors.New("invalid PAR2 set: sliceByteCount is zero")
		}
		shards := (uint64(f.ByteCount) + uint64(d.sliceByteCount) - 1) / uint64(d.sliceByteCount)
		if shards > 32768 {
			d.mu.Unlock()
			return fmt.Errorf("invalid PAR2 set: file %s block count (%d) exceeds specification limit (32768)", f.Filename, shards)
		}
		totalShards += int(shards)
		if totalShards > 32768 {
			d.mu.Unlock()
			return fmt.Errorf("invalid PAR2 set: total recovery block count (%d) exceeds specification limit (32768)", totalShards)
		}

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

	window, err := newCRC32Window(d.sliceByteCount)
	if err != nil {
		return err
	}

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

	lookupTable := newCRCLookupTable(checksumMap)

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
	for _, fDesc := range d.protectedFiles {
		if ctx.Err() != nil {
			break
		}

		scanWg.Add(1)
		go func(fd FileDescPacket) {
			defer scanWg.Done()

			err := d.scanFile(ctx, fd, window, sem, lookupTable, matchChan)
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
	for _, fd := range d.protectedFiles {
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
			_, copyErr := io.Copy(hasher, f)
			f.Close()
			if copyErr != nil {
				d.logger.WarnContext(ctx, "I/O error during MD5 verification", "file", fd.Filename, "err", copyErr)
				state.HashMismatch = true
				continue
			}
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

func (d *Decoder) scanFile(ctx context.Context, fd FileDescPacket, window *crc32Window, sem chan struct{}, lookupTable *crcLookupTable, matchChan chan<- matchEvent) error {
	f, err := d.root.Open(fd.Filename)
	if errors.Is(err, fs.ErrNotExist) {
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
	var chunkErr error
	var chunkErrMu sync.Mutex

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

			if err := d.scanChunk(ctx, f, fd.FileID, window, start, end, lookupTable, matchChan); err != nil {
				d.logger.ErrorContext(ctx, "I/O error during chunk scan", "file", fd.Filename, "offset", start, "err", err)
				chunkErrMu.Lock()
				if chunkErr == nil {
					chunkErr = err
				}
				chunkErrMu.Unlock()
			}
		}(i)
	}

	chunkWg.Wait()

	if chunkErr != nil {
		return chunkErr
	}

	// Natively verify the last partial block if the file size is not a multiple of sliceByteCount
	shards := (uint64(fd.ByteCount) + uint64(d.sliceByteCount) - 1) / uint64(d.sliceByteCount)
	if uint64(fd.ByteCount)%uint64(d.sliceByteCount) != 0 {
		lastBlockStart := int64((shards - 1) * uint64(d.sliceByteCount))
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
		if locations, found := lookupTable.Lookup(crcVal); found {
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

func (d *Decoder) scanChunk(ctx context.Context, f *os.File, sourceFileID FileID, window *crc32Window, start, end int64, lookupTable *crcLookupTable, matchChan chan<- matchEvent) error {
	bufferSize := end - start
	if bufferSize < int64(d.sliceByteCount) {
		return nil
	}
	data := make([]byte, bufferSize)
	_, err := f.ReadAt(data, start)
	if err != nil && err != io.EOF {
		return fmt.Errorf("ReadAt offset %d: %w", start, err)
	}

	var crcSlice uint32
	justMissed := false

	for j := 0; j <= len(data)-d.sliceByteCount; {
		// Only check context cancellation once every 65,536 bytes to eliminate atomic lock overheads in tight loops
		if j&0xFFFF == 0 {
			if ctx.Err() != nil {
				return nil
			}
		}

		slice := data[j : j+d.sliceByteCount]
		if justMissed {
			crcSlice = window.update(crcSlice, data[j-1], slice[len(slice)-1])
		} else {
			crcSlice = crc32.ChecksumIEEE(slice)
		}

		locations, found := lookupTable.Lookup(crcSlice)
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
	return nil
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

	// Validate that all parity shards have the correct length. A malicious PAR2
	// file could contain a recovery packet whose data is shorter than sliceByteCount
	// (while still passing the per-packet MD5 integrity check). Without this guard,
	// the slice expression parityBytes[offset:offset+currChunkSize] would panic.
	for exp, parityBytes := range d.parityShards {
		if len(parityBytes) != d.sliceByteCount {
			return fmt.Errorf("recovery packet exponent %d has data length %d, expected sliceByteCount %d",
				exp, len(parityBytes), d.sliceByteCount)
		}
	}

	// Total data shards in PAR2 set
	totalDataShards := 0
	for _, f := range d.protectedFiles {
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
	denom := int64(totalDataShards + counts.UnusableDataShardCount)
	if denom <= 0 {
		return errors.New("invalid shard configuration for repair")
	}
	chunkSize := d.memoryLimit / denom
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
	for _, f := range d.protectedFiles {
		fileIDToFilename[f.FileID] = f.Filename
	}

	flatLocs := make([]flattenedLocation, totalDataShards)
	k := 0
	for _, f := range d.protectedFiles {
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
	for _, f := range d.protectedFiles {
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
	for _, fd := range d.protectedFiles {
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

	// NOTE: os.ReadDir is used here instead of d.root because Go's os.Root API
	// does not expose a directory listing method. This is an accepted limitation:
	// d.absRootDir was resolved via filepath.EvalSymlinks at construction time,
	// and all actual file opens below go through d.root.Open which is sandboxed.
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

	// Reject volume files exceeding maximum allowed size to prevent memory exhaustion.
	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat volume file: %w", err)
	}
	if stat.Size() > d.maxFileSize {
		return fmt.Errorf("volume file %s exceeds maximum allowed size (%d bytes > %d byte limit)", filename, stat.Size(), d.maxFileSize)
	}

	// Use a buffered reader to stream packet parsing without loading the whole file into memory.
	// This prevents OOM attacks from massive recovery volume files.
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		h, err := ReadHeader(f)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		bodyLen := int64(h.Length - 64)
		if bodyLen < 0 || bodyLen > d.maxPacketSize {
			return errors.New("packet body exceeds safe engine limits")
		}
		body := make([]byte, bodyLen)
		_, err = io.ReadFull(f, body)
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
			if _, exists := d.parityShards[p.Exponent]; exists {
				d.logger.WarnContext(ctx, "duplicate recovery packet exponent, skipping", "exponent", p.Exponent, "file", filename)
			} else {
				d.parityShards[p.Exponent] = p.Data
			}
			d.mu.Unlock()
		}
	}

	return nil
}

type crcTableEntry struct {
	crc   uint32
	valid bool
	locs  []checksumLocation
}

type crcLookupTable struct {
	mask  uint32
	table []crcTableEntry
}

func newCRCLookupTable(checksumMap map[uint32][]checksumLocation) *crcLookupTable {
	numEntries := len(checksumMap)
	size := 16
	for size < numEntries*4 {
		size *= 2
	}

	t := &crcLookupTable{
		mask:  uint32(size - 1),
		table: make([]crcTableEntry, size),
	}

	for crc, locs := range checksumMap {
		idx := crc & t.mask
		for {
			if !t.table[idx].valid {
				t.table[idx] = crcTableEntry{
					crc:   crc,
					valid: true,
					locs:  locs,
				}
				break
			}
			idx = (idx + 1) & t.mask
		}
	}
	return t
}

func (t *crcLookupTable) Lookup(crc uint32) ([]checksumLocation, bool) {
	idx := crc & t.mask
	for {
		entry := &t.table[idx]
		if !entry.valid {
			return nil, false
		}
		if entry.crc == crc {
			return entry.locs, true
		}
		idx = (idx + 1) & t.mask
	}
}
