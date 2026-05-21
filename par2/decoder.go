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
	"sync/atomic"

	"github.com/hobeone/par2engine/rs"
)

type md5Closer interface {
	Close()
}

type scanProgress struct {
	scannedBytes int64
	totalBytes   int64
	progressChan chan<- Progress
}

func (p *scanProgress) add(bytes int64) {
	if p == nil || p.progressChan == nil {
		return
	}
	scanned := atomic.AddInt64(&p.scannedBytes, bytes)
	pct := min(float64(scanned)/float64(p.totalBytes)*100, 100.0)
	p.progressChan <- Progress{
		Phase:   "verifying",
		Current: scanned,
		Total:   p.totalBytes,
		Percent: pct,
	}
}

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
	Verified       bool            // true if full-file MD5 was already verified OK
	RenameSource   string          // non-empty when a candidate file is a perfect content match under a different name
	ShardLocations []ShardLocation // maps expected shardIndex -> where it is actually located
}

// ShardCounts captures statistical shard availability status.
type ShardCounts struct {
	UsableDataShardCount     int
	UnusableDataShardCount   int
	UsableParityShardCount   int
	UnusableParityShardCount int
	RenamesNeeded            int // files whose content is intact in a candidate under a different name
}

func (sc ShardCounts) RepairNeeded() bool {
	return sc.UnusableDataShardCount > 0 || sc.RenamesNeeded > 0
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

	root       *os.Root // sandboxed target folder directory root (Go 1.24+)

	sliceByteCount int
	recoverySetID  [16]byte
	protectedFiles []FileDescPacket
	fileChecksums  map[FileID]*IFSCPacket
	parityShards   map[uint16][]byte // exponent -> parity bytes loaded from par2 files

	fileIntegrity    map[FileID]*FileIntegrityState
	candidateFiles   map[string]FileID // extra files to scan; path → synthetic FileID
	parityFileBlocks map[string]int    // par2 filename → number of recovery blocks it contributes
	mu               sync.Mutex        // protects shared state updates
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

// DecoderOptions contains configuration for the PAR2 decoder.
type DecoderOptions struct {
	NumGoroutines int
	MemoryLimit   int64
	MaxFileSize   int64
	MaxPacketSize int64
	Logger        *slog.Logger
}

// NewDecoder opens a sandboxed target directory relative to the index par2 file,
// parses the index par2 manifest, and returns a Decoder.
func NewDecoder(ctx context.Context, par2Path string, opts DecoderOptions) (*Decoder, error) {
	if opts.NumGoroutines <= 0 {
		opts.NumGoroutines = rs.DefaultNumGoroutines()
	}
	if opts.MemoryLimit <= 0 {
		opts.MemoryLimit = 16 * 1024 * 1024 // 16MB default memory limit
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 100 * 1024 * 1024 // 100MB default index file size limit
	}
	if opts.MaxPacketSize <= 0 {
		opts.MaxPacketSize = 128 * 1024 * 1024 // default packet body limit
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
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
		numGoroutines:    opts.NumGoroutines,
		memoryLimit:      opts.MemoryLimit,
		maxFileSize:      opts.MaxFileSize,
		maxPacketSize:    opts.MaxPacketSize,
		logger:           opts.Logger,
		root:             root,
		fileChecksums:    make(map[FileID]*IFSCPacket),
		parityShards:     make(map[uint16][]byte),
		fileIntegrity:    make(map[FileID]*FileIntegrityState),
		parityFileBlocks: make(map[string]int),
	}

	err = d.loadIndexFile(ctx, indexFilename)
	if err != nil {
		_ = root.Close()
		return nil, err
	}

	err = d.loadVolumeFiles(ctx, indexFilename)
	if err != nil {
		_ = root.Close()
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

// AddCandidateFile registers an extra file to scan during VerifyScans. Use this
// when a file has been renamed or is otherwise not recognised by its name but
// its content may match one of the protected files in the PAR2 set. path must
// be relative to the PAR2 directory and within the sandbox (no traversal).
// Call before VerifyScans; duplicate registrations are silently ignored.
func (d *Decoder) AddCandidateFile(path string) error {
	defanged, err := DefangPath(path)
	if err != nil {
		return fmt.Errorf("invalid candidate file path: %w", err)
	}
	if d.candidateFiles == nil {
		d.candidateFiles = make(map[string]FileID)
	}
	if _, exists := d.candidateFiles[defanged]; !exists {
		// Synthetic FileID: deterministic hash that won't collide with real PAR2
		// FileIDs (which are MD5 of 16KHash ‖ byteCount ‖ filename).
		d.candidateFiles[defanged] = FileID(md5.Sum([]byte("candidate:" + defanged)))
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
	defer func() { _ = f.Close() }()

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
			d.logger.DebugContext(ctx, "Parsed SliceByteCount", "size", p.SliceByteCount)

		case FileDescPacketType:
			p, err := ParseFileDescPacket(body)
			if err != nil {
				return err
			}
			d.protectedFiles = append(d.protectedFiles, *p)
			d.logger.DebugContext(ctx, "PAR2 set contains protected file", "file", p.Filename, "size", p.ByteCount)

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
				d.parityFileBlocks[indexFilename]++
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

	renamesNeeded := 0
	for _, state := range d.fileIntegrity {
		if state.RenameSource != "" {
			renamesNeeded++
		}
	}

	return ShardCounts{
		UsableDataShardCount:     usableData,
		UnusableDataShardCount:   unusableData,
		UsableParityShardCount:   len(d.parityShards),
		UnusableParityShardCount: 0,
		RenamesNeeded:            renamesNeeded,
	}
}

func (d *Decoder) initFileIntegrity() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.fileIntegrity = make(map[FileID]*FileIntegrityState)
	totalShards := 0
	for _, f := range d.protectedFiles {
		if d.sliceByteCount == 0 {
			return errors.New("invalid PAR2 set: sliceByteCount is zero")
		}
		shards := (uint64(f.ByteCount) + uint64(d.sliceByteCount) - 1) / uint64(d.sliceByteCount)
		if shards > 32768 {
			return fmt.Errorf("invalid PAR2 set: file %s block count (%d) exceeds specification limit (32768)", f.Filename, shards)
		}
		totalShards += int(shards)
		if totalShards > 32768 {
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
	return nil
}

// VerifyScans checks the integrity of all protected files against the PAR2 set.
func (d *Decoder) VerifyScans(ctx context.Context, progressChan chan<- Progress) error {
	if err := d.initFileIntegrity(); err != nil {
		return err
	}

	// ── Phase 1: list protected files sorted alphabetically ──────────────────
	sorted := make([]FileDescPacket, len(d.protectedFiles))
	copy(sorted, d.protectedFiles)
	slices.SortFunc(sorted, func(a, b FileDescPacket) int { return strings.Compare(a.Filename, b.Filename) })
	d.logger.InfoContext(ctx, fmt.Sprintf("PAR2 set protects %d file(s):", len(sorted)))
	for _, fd := range sorted {
		d.logger.InfoContext(ctx, fmt.Sprintf("  %s (%d bytes)", fd.Filename, fd.ByteCount))
	}

	// ── Phase 2: list PAR2 archives with recovery block counts ───────────────
	parityFiles := make([]string, 0, len(d.parityFileBlocks))
	for name := range d.parityFileBlocks {
		parityFiles = append(parityFiles, name)
	}
	slices.Sort(parityFiles)
	d.logger.InfoContext(ctx, fmt.Sprintf("Found %d recovery archive(s):", len(parityFiles)))
	for _, name := range parityFiles {
		d.logger.InfoContext(ctx, fmt.Sprintf("  %s (%d recovery blocks)", name, d.parityFileBlocks[name]))
	}

	// ── Phase 3: list candidate files ────────────────────────────────────────
	if len(d.candidateFiles) > 0 {
		d.logger.InfoContext(ctx, fmt.Sprintf("Candidate file(s) to consider (%d):", len(d.candidateFiles)))
		for path := range d.candidateFiles {
			d.logger.InfoContext(ctx, fmt.Sprintf("  %s", path))
		}
	}

	// ── Phase 4: quick existence check — log missing files up front ──────────
	for _, fd := range d.protectedFiles {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f, err := d.root.Open(fd.Filename)
		if errors.Is(err, fs.ErrNotExist) {
			d.mu.Lock()
			d.fileIntegrity[fd.FileID].Missing = true
			d.mu.Unlock()
			d.logger.InfoContext(ctx, "File not found on disk", "file", fd.Filename)
			continue
		} else if err != nil {
			return err
		}
		_ = f.Close()
	}

	// ── Phase 5: pre-scan candidates for full content matches ────────────────
	// For each candidate, compute a quick 16 KB hash then the full MD5. If it
	// matches a missing protected file, populate ShardLocations directly and
	// skip the expensive sliding-window block scan for that candidate.
	resolvedCandidates := d.prescanCandidateMatches(ctx)

	// ── Phase 5a: pre-scan protected files for perfect matches ───────────────
	// Check if any protected files are already 100% healthy on disk to skip
	// the sliding-window scan for them.
	d.prescanProtectedMatches(ctx)

	// ── Phase 6: build checksum map and run the block-level scan ─────────────
	// Calculate total bytes to scan (only files not missing and not pre-verified)
	var totalBytesToScan int64
	for _, fd := range d.protectedFiles {
		d.mu.Lock()
		state := d.fileIntegrity[fd.FileID]
		missing := state.Missing
		verified := state.Verified
		d.mu.Unlock()
		if !missing && !verified {
			totalBytesToScan += int64(fd.ByteCount)
		}
	}

	var progress *scanProgress
	if progressChan != nil && totalBytesToScan > 0 {
		progress = &scanProgress{
			totalBytes:   totalBytesToScan,
			progressChan: progressChan,
		}
		// Initial 0% progress update
		progressChan <- Progress{
			Phase:   "verifying",
			Current: 0,
			Total:   totalBytesToScan,
			Percent: 0.0,
		}
	}

	window, err := newCRC32Window(d.sliceByteCount)
	if err != nil {
		return err
	}

	checksumMap := make(map[uint32][]checksumLocation)
	for fID, ifsc := range d.fileChecksums {
		// Security guard: ignore IFSC checksums for unknown FileIDs to prevent
		// nil-pointer dereference panic in the collector goroutine.
		if _, exists := d.fileIntegrity[fID]; !exists {
			d.logger.WarnContext(ctx, "Ignoring IFSC packet for unknown file ID", "fileID", fmt.Sprintf("%x", fID[:4]))
			continue
		}
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

	var collectorWg sync.WaitGroup
	collectorWg.Go(func() {
		for match := range matchChan {
			d.mu.Lock()
			state := d.fileIntegrity[match.targetFileID]
			if state.ShardLocations[match.shardIndex].Offset == -1 {
				d.logger.Debug("Block match found",
					"targetFile", state.Filename,
					"shardIdx", match.shardIndex,
					"sourceFileID", fmt.Sprintf("%x", match.sourceFileID[:4]),
					"offset", match.offset)
				state.ShardLocations[match.shardIndex] = ShardLocation{
					FileID: match.sourceFileID,
					Offset: match.offset,
				}
			}
			d.mu.Unlock()
		}
	})

	sem := make(chan struct{}, d.numGoroutines)

	// Scan protected files that exist on disk and are not already pre-verified.
	for _, fDesc := range d.protectedFiles {
		if ctx.Err() != nil {
			break
		}
		d.mu.Lock()
		state := d.fileIntegrity[fDesc.FileID]
		missing := state.Missing
		verified := state.Verified
		d.mu.Unlock()
		if missing || verified {
			continue
		}
		scanWg.Add(1)
		go func(fd FileDescPacket) {
			defer scanWg.Done()
			if err := d.scanFile(ctx, fd, window, sem, lookupTable, matchChan, progress); err != nil {
				d.logger.ErrorContext(ctx, "failed to scan file", "file", fd.Filename, "err", err)
				setScanErr(err)
			}
		}(fDesc)
	}

	// Scan candidate files not already resolved by the pre-scan phase.
	// Also skip any candidate whose path matches a protected file: scanFile
	// already covers that file, and running both concurrently causes a race
	// where the collector may attribute blocks to the synthetic FileID.
	protectedNames := make(map[string]bool, len(d.protectedFiles))
	for _, fd := range d.protectedFiles {
		protectedNames[fd.Filename] = true
	}
	for path, fileID := range d.candidateFiles {
		if ctx.Err() != nil {
			break
		}
		if resolvedCandidates[path] || protectedNames[path] {
			continue
		}
		scanWg.Add(1)
		go func(path string, fileID FileID) {
			defer scanWg.Done()
			if err := d.scanCandidateFile(ctx, path, fileID, window, sem, lookupTable, matchChan); err != nil {
				d.logger.ErrorContext(ctx, "failed to scan candidate file", "path", path, "err", err)
				setScanErr(err)
			}
		}(path, fileID)
	}

	scanWg.Wait()
	close(matchChan)
	collectorWg.Wait()

	if scanErr != nil {
		return scanErr
	}

	// Post-scan global hash check
	d.logger.DebugContext(ctx, "Starting post-scan MD5 hash verification phase")
	d.mu.Lock()
	for _, fd := range d.protectedFiles {
		state := d.fileIntegrity[fd.FileID]
		if state.Verified {
			continue
		}
		if state.SizeMismatch {
			continue
		}
		if state.Missing {
			// The file doesn't exist under its expected name, but a candidate
			// may have all the blocks. Check for a rename match before giving up.
			if rename := d.detectRenameCandidate(ctx, fd, state); rename != "" {
				state.Missing = false
				state.RenameSource = rename
				d.logger.InfoContext(ctx, "File found under different name",
					"expected", fd.Filename,
					"found", rename)
			}
			continue
		}
		// Verify overall file hash if all shards are matched at expected consecutive offsets
		allConsecutive := true
		for idx, loc := range state.ShardLocations {
			expected := int64(idx * d.sliceByteCount)
			if loc.Offset != expected || loc.FileID != fd.FileID {
				allConsecutive = false
				d.logger.Debug("File requires partial reconstruction or reordering",
					"file", fd.Filename,
					"shardIdx", idx,
					"expectedOffset", expected,
					"actualOffset", loc.Offset)
				break
			}
		}

		if allConsecutive {
			// Standard full file MD5 check — unlock while doing I/O to avoid holding
			// the mutex across potentially slow disk reads.
			d.mu.Unlock()
			d.logger.DebugContext(ctx, "Running MD5 hash check", "file", fd.Filename)
			f, err := d.root.Open(fd.Filename)
			if err != nil {
				d.mu.Lock()
				state.Missing = true
				continue
			}
			hasher := md5.New()
			_, copyErr := io.Copy(hasher, f)
			_ = f.Close()
			d.mu.Lock()
			if copyErr != nil {
				d.logger.WarnContext(ctx, "I/O error during MD5 verification", "file", fd.Filename, "err", copyErr)
				state.HashMismatch = true
				continue
			}
			var fileHash [16]byte
			copy(fileHash[:], hasher.Sum(nil))
			if fileHash != fd.Hash {
				d.logger.WarnContext(ctx, "File hash verification FAILED",
					"file", fd.Filename,
					"expected", fmt.Sprintf("%x", fd.Hash),
					"actual", fmt.Sprintf("%x", fileHash))
				state.HashMismatch = true
			} else {
				d.logger.DebugContext(ctx, "File hash verified OK", "file", fd.Filename)
			}
		} else if rename := d.detectRenameCandidate(ctx, fd, state); rename != "" {
			// All shards found in a single candidate file at consecutive offsets
			// with a matching MD5 — this is just a misnamed file, not corruption.
			state.RenameSource = rename
			d.logger.InfoContext(ctx, "File found under different name",
				"expected", fd.Filename,
				"found", rename)
		} else {
			state.HashMismatch = true
		}
	}

	// Compute counts while still holding the lock — calling d.ShardCounts() here
	// would deadlock because it also acquires d.mu.
	usableData, unusableData, renamesNeeded := 0, 0, 0
	for _, state := range d.fileIntegrity {
		for _, loc := range state.ShardLocations {
			if loc.Offset == -1 {
				unusableData++
			} else {
				usableData++
			}
		}
		if state.RenameSource != "" {
			renamesNeeded++
		}
	}
	finalCounts := ShardCounts{
		UsableDataShardCount:   usableData,
		UnusableDataShardCount: unusableData,
		UsableParityShardCount: len(d.parityShards),
		RenamesNeeded:          renamesNeeded,
	}
	// Per-file status report (logged before releasing the lock so state is consistent).
	okCount, missingCount, damagedCount, renameCount := 0, 0, 0, 0
	for _, fd := range d.protectedFiles {
		state := d.fileIntegrity[fd.FileID]
		switch {
		case state.Missing:
			d.logger.WarnContext(ctx, "File status: MISSING", "file", fd.Filename)
			missingCount++
		case state.SizeMismatch:
			d.logger.WarnContext(ctx, "File status: SIZE MISMATCH",
				"file", fd.Filename,
				"expected", fd.ByteCount)
			damagedCount++
		case state.HashMismatch:
			missing := 0
			for _, loc := range state.ShardLocations {
				if loc.Offset == -1 {
					missing++
				}
			}
			if missing > 0 {
				d.logger.WarnContext(ctx, "File status: DAMAGED",
					"file", fd.Filename,
					"missingBlocks", missing,
					"totalBlocks", len(state.ShardLocations))
			} else {
				d.logger.WarnContext(ctx, "File status: CORRUPT (hash mismatch, all blocks present)",
					"file", fd.Filename)
			}
			damagedCount++
		case state.RenameSource != "":
			d.logger.InfoContext(ctx, "File status: MISNAMED (will rename)",
				"expected", fd.Filename,
				"found", state.RenameSource)
			renameCount++
		default:
			d.logger.InfoContext(ctx, "File status: OK", "file", fd.Filename)
			okCount++
		}
	}
	d.mu.Unlock()

	d.logger.DebugContext(ctx, "Post-scan complete",
		"usableDataShards", finalCounts.UsableDataShardCount,
		"unusableDataShards", finalCounts.UnusableDataShardCount,
		"usableParityShards", finalCounts.UsableParityShardCount)

	// Verification summary.
	d.logger.InfoContext(ctx, "Verification summary",
		"totalFiles", len(d.protectedFiles),
		"ok", okCount,
		"missing", missingCount,
		"damaged", damagedCount,
		"misnamed", renameCount,
		"recoveryBlocks", len(d.parityShards))

	switch {
	case finalCounts.UnusableDataShardCount > 0:
		d.logger.Warn("Verification found missing or corrupt blocks",
			"missingBlocks", finalCounts.UnusableDataShardCount,
			"damagedFiles", damagedCount,
			"missingFiles", missingCount,
			"availableParity", finalCounts.UsableParityShardCount)
	case finalCounts.RenamesNeeded > 0:
		d.logger.Info("All file content is intact — repair will rename misnamed file(s)",
			"filesToRename", finalCounts.RenamesNeeded)
	default:
		d.logger.Info("All files verified OK.")
	}

	return ctx.Err()
}

// prescanCandidateMatches runs a full-file MD5 check on each candidate before
// the block-level scan. If a candidate is a perfect content match for a missing
// protected file it populates ShardLocations directly (skipping the sliding-window
// scan) and sets RenameSource. Returns the set of candidate paths that were resolved.
func (d *Decoder) prescanCandidateMatches(ctx context.Context) map[string]bool {
	resolved := make(map[string]bool)
	if len(d.candidateFiles) == 0 {
		return resolved
	}

	// Index missing protected files by (size, SixteenKHash) for fast lookup.
	type quickKey struct {
		size         int64
		sixteenKHash [16]byte
	}
	missingByQuickKey := make(map[quickKey]*FileDescPacket)
	d.mu.Lock()
	for i := range d.protectedFiles {
		fd := &d.protectedFiles[i]
		if d.fileIntegrity[fd.FileID].Missing {
			missingByQuickKey[quickKey{int64(fd.ByteCount), fd.SixteenKHash}] = fd
		}
	}
	d.mu.Unlock()

	if len(missingByQuickKey) == 0 {
		return resolved
	}

	const quickHashSize = 16 * 1024

	for candidatePath, candidateID := range d.candidateFiles {
		if ctx.Err() != nil {
			break
		}

		f, err := d.root.Open(candidatePath)
		if err != nil {
			// File not accessible — mark resolved so the block scan also skips it.
			resolved[candidatePath] = true
			continue
		}

		stat, err := f.Stat()
		if err != nil {
			_ = f.Close()
			continue
		}
		fileSize := stat.Size()

		// Quick filter: read first 16 KB and hash it.
		quick := make([]byte, min(quickHashSize, int(fileSize)))
		n, _ := f.ReadAt(quick, 0)
		quickHash := md5.Sum(quick[:n])

		fd, ok := missingByQuickKey[quickKey{fileSize, quickHash}]
		if !ok {
			_ = f.Close()
			continue
		}

		// 16 KB matched — compute full-file MD5 to confirm.
		d.logger.InfoContext(ctx, "Pre-verifying candidate file...", "candidate", candidatePath, "matchedFile", fd.Filename, "size", fileSize)
		hasher := md5.New()
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			_ = f.Close()
			continue
		}
		_, copyErr := io.Copy(hasher, f)
		_ = f.Close()
		if copyErr != nil {
			continue
		}
		var fullHash [16]byte
		copy(fullHash[:], hasher.Sum(nil))
		if fullHash != fd.Hash {
			continue
		}

		// Perfect match: populate ShardLocations and mark for rename.
		d.mu.Lock()
		state := d.fileIntegrity[fd.FileID]
		state.RenameSource = candidatePath
		state.Verified = true
		for i := range state.ShardLocations {
			state.ShardLocations[i] = ShardLocation{
				FileID: candidateID,
				Offset: int64(i * d.sliceByteCount),
			}
		}
		d.mu.Unlock()

		d.logger.DebugContext(ctx, "Candidate pre-scan: full content match confirmed",
			"candidate", candidatePath, "target", fd.Filename)
		resolved[candidatePath] = true
	}

	return resolved
}

// prescanProtectedMatches checks if any protected files are already perfectly healthy
// on disk by comparing their size, 16 KB hash, and full-file MD5.
// If a file matches, it populates ShardLocations directly and skips the sliding-window scan.
func (d *Decoder) prescanProtectedMatches(ctx context.Context) {
	const quickHashSize = 16 * 1024

	for i := range d.protectedFiles {
		if ctx.Err() != nil {
			break
		}
		fd := &d.protectedFiles[i]

		d.mu.Lock()
		missing := d.fileIntegrity[fd.FileID].Missing
		d.mu.Unlock()
		if missing {
			continue
		}

		f, err := d.root.Open(fd.Filename)
		if err != nil {
			continue
		}

		stat, err := f.Stat()
		if err != nil {
			_ = f.Close()
			continue
		}
		fileSize := stat.Size()

		if fileSize != int64(fd.ByteCount) {
			_ = f.Close()
			continue
		}

		// Quick filter: read first 16 KB and hash it.
		quick := make([]byte, min(quickHashSize, int(fileSize)))
		n, err := f.ReadAt(quick, 0)
		if err != nil && err != io.EOF {
			_ = f.Close()
			continue
		}
		quickHash := md5.Sum(quick[:n])

		if quickHash != fd.SixteenKHash {
			_ = f.Close()
			continue
		}

		// 16 KB matched — compute full-file MD5 to confirm.
		d.logger.InfoContext(ctx, "Pre-verifying file...", "file", fd.Filename, "size", fileSize)
		hasher := md5.New()
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			_ = f.Close()
			continue
		}
		_, copyErr := io.Copy(hasher, f)
		_ = f.Close()
		if copyErr != nil {
			continue
		}
		var fullHash [16]byte
		copy(fullHash[:], hasher.Sum(nil))
		if fullHash != fd.Hash {
			continue
		}

		// Perfect match: populate ShardLocations directly
		d.mu.Lock()
		state := d.fileIntegrity[fd.FileID]
		state.Missing = false
		state.SizeMismatch = false
		state.HashMismatch = false
		state.Verified = true
		for idx := range state.ShardLocations {
			state.ShardLocations[idx] = ShardLocation{
				FileID: fd.FileID,
				Offset: int64(idx * d.sliceByteCount),
			}
		}
		d.mu.Unlock()

		d.logger.DebugContext(ctx, "Protected file pre-scan: verified OK (skipping sliding scan)", "file", fd.Filename)
	}
}

// detectRenameCandidate checks whether all shards of a protected file were
// found in a single candidate file at consecutive offsets. If so, it verifies
// the candidate's full-file MD5 against the expected hash. Returns the
// candidate path if it's a perfect match, or "" otherwise.
//
// Must be called while d.mu is held. Temporarily releases the lock for I/O.
func (d *Decoder) detectRenameCandidate(ctx context.Context, fd FileDescPacket, state *FileIntegrityState) string {
	if len(state.ShardLocations) == 0 {
		return ""
	}

	// Check: all shards from the same single candidate file at consecutive offsets.
	firstLoc := state.ShardLocations[0]
	if firstLoc.Offset == -1 {
		return "" // first shard missing
	}

	// Must be a candidate file, not the target itself.
	candidateID := firstLoc.FileID
	if candidateID == fd.FileID {
		return "" // shard is from the target file itself, not a candidate
	}

	// Look up the candidate path.
	var candidatePath string
	for path, id := range d.candidateFiles {
		if id == candidateID {
			candidatePath = path
			break
		}
	}
	if candidatePath == "" {
		return "" // source isn't a registered candidate
	}
	if candidatePath == fd.Filename {
		return "" // same filename — not a rename
	}

	// Verify all shards come from this same candidate at consecutive offsets.
	for idx, loc := range state.ShardLocations {
		expected := int64(idx * d.sliceByteCount)
		if loc.FileID != candidateID || loc.Offset != expected {
			return "" // mixed sources or non-consecutive
		}
	}

	// All shards match structurally. Run full-file MD5 to confirm content integrity.
	// Release the lock during I/O.
	d.mu.Unlock()
	d.logger.DebugContext(ctx, "Running MD5 hash check on rename candidate",
		"expected", fd.Filename, "candidate", candidatePath)
	f, err := d.root.Open(candidatePath)
	if err != nil {
		d.mu.Lock()
		return ""
	}
	hasher := md5.New()
	_, copyErr := io.Copy(hasher, f)
	_ = f.Close()
	d.mu.Lock()
	if copyErr != nil {
		d.logger.WarnContext(ctx, "I/O error during rename candidate MD5 check",
			"candidate", candidatePath, "err", copyErr)
		return ""
	}
	var fileHash [16]byte
	copy(fileHash[:], hasher.Sum(nil))
	if fileHash != fd.Hash {
		d.logger.DebugContext(ctx, "Rename candidate MD5 mismatch",
			"candidate", candidatePath,
			"expected", fmt.Sprintf("%x", fd.Hash),
			"actual", fmt.Sprintf("%x", fileHash))
		return ""
	}
	return candidatePath
}

// renameMisnamedFiles renames candidate files to their expected names for any
// protected file where RenameSource is set. Returns the number of files
// successfully renamed.
func (d *Decoder) renameMisnamedFiles(ctx context.Context) int {
	renamed := 0
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, fd := range d.protectedFiles {
		state := d.fileIntegrity[fd.FileID]
		if state.RenameSource == "" {
			continue
		}

		// Ensure the target directory exists using sandbox root.
		if dir := filepath.Dir(fd.Filename); dir != "." {
			if err := d.root.MkdirAll(dir, 0755); err != nil {
				d.logger.WarnContext(ctx, "Failed to create directory for rename, falling back to repair",
					"dir", dir, "err", err)
				state.RenameSource = ""
				state.HashMismatch = true
				continue
			}
		}

		if err := d.root.Rename(state.RenameSource, fd.Filename); err != nil {
			d.logger.WarnContext(ctx, "Rename failed, falling back to repair",
				"from", state.RenameSource, "to", fd.Filename, "err", err)
			// Clear rename state and mark as needing reconstruction.
			state.RenameSource = ""
			state.HashMismatch = true
			continue
		}

		d.logger.InfoContext(ctx, "Renamed misnamed file",
			"from", state.RenameSource, "to", fd.Filename)

		// Update integrity state: file is now healthy under its correct name.
		state.RenameSource = ""
		state.Missing = false
		state.HashMismatch = false
		for idx := range state.ShardLocations {
			state.ShardLocations[idx] = ShardLocation{
				FileID: fd.FileID,
				Offset: int64(idx * d.sliceByteCount),
			}
		}
		renamed++
	}
	return renamed
}

func (d *Decoder) scanFile(ctx context.Context, fd FileDescPacket, window *crc32Window, sem chan struct{}, lookupTable *crcLookupTable, matchChan chan<- matchEvent, progress *scanProgress) error {
	f, err := d.root.Open(fd.Filename)
	if errors.Is(err, fs.ErrNotExist) {
		// Phase 4 of VerifyScans already logged and set Missing — nothing to do here.
		d.mu.Lock()
		d.fileIntegrity[fd.FileID].Missing = true
		d.mu.Unlock()
		return nil
	} else if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return err
	}

	d.mu.Lock()
	state := d.fileIntegrity[fd.FileID]
	if stat.Size() != int64(fd.ByteCount) {
		d.logger.Warn("File size mismatch", "file", fd.Filename, "expected", fd.ByteCount, "actual", stat.Size())
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
	for i := range numChunks {
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
			end := min(start+scanChunkSize+int64(d.sliceByteCount)-1, fileSize)

			if err := d.scanChunk(ctx, f, fd.FileID, window, start, end, lookupTable, matchChan); err != nil {
				d.logger.ErrorContext(ctx, "I/O error during chunk scan", "file", fd.Filename, "offset", start, "err", err)
				chunkErrMu.Lock()
				if chunkErr == nil {
					chunkErr = err
				}
				chunkErrMu.Unlock()
			} else {
				progress.add(min(scanChunkSize, fileSize-start))
			}
		}(i)
	}

	chunkWg.Wait()

	if chunkErr != nil {
		return chunkErr
	}

	return d.scanLastPartialBlock(f, fd.FileID, int64(fd.ByteCount), lookupTable, matchChan)
}

// scanLastPartialBlock checks the final block of a file when its size is not a
// multiple of sliceByteCount. The block is zero-padded to sliceByteCount before
// hashing, matching the PAR2 specification.
func (d *Decoder) scanLastPartialBlock(f *os.File, sourceFileID FileID, byteCount int64, lookupTable *crcLookupTable, matchChan chan<- matchEvent) error {
	if uint64(byteCount)%uint64(d.sliceByteCount) == 0 {
		return nil
	}
	shards := (uint64(byteCount) + uint64(d.sliceByteCount) - 1) / uint64(d.sliceByteCount)
	lastBlockStart := int64((shards - 1) * uint64(d.sliceByteCount))
	lastBlockLen := byteCount - lastBlockStart

	paddedBlock := make([]byte, d.sliceByteCount)
	if _, err := f.ReadAt(paddedBlock[:lastBlockLen], lastBlockStart); err != nil && err != io.EOF {
		return err
	}

	crcVal := crc32.ChecksumIEEE(paddedBlock)
	if locations, found := lookupTable.Lookup(crcVal); found {
		blockHash := md5.Sum(paddedBlock)
		for _, loc := range locations {
			if loc.md5Hash == blockHash {
				matchChan <- matchEvent{
					targetFileID: loc.fileID,
					shardIndex:   loc.shardIndex,
					sourceFileID: sourceFileID,
					offset:       lastBlockStart,
				}
			}
		}
	}
	return nil
}

// scanCandidateFile scans an extra file (registered via AddCandidateFile) for
// shard matches against any protected file in the PAR2 set.
func (d *Decoder) scanCandidateFile(ctx context.Context, path string, fileID FileID, window *crc32Window, sem chan struct{}, lookupTable *crcLookupTable, matchChan chan<- matchEvent) error {
	f, err := d.root.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		d.logger.WarnContext(ctx, "candidate file not found, skipping", "path", path)
		return nil
	} else if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return err
	}
	fileSize := stat.Size()
	if fileSize == 0 {
		return nil
	}

	const scanChunkSize = 32 * 1024 * 1024
	var chunkWg sync.WaitGroup
	var chunkErr error
	var chunkErrMu sync.Mutex

	numChunks := (fileSize + scanChunkSize - 1) / scanChunkSize
	for i := range numChunks {
		if ctx.Err() != nil {
			break
		}
		chunkWg.Add(1)
		go func(chunkIdx int64) {
			defer chunkWg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			start := chunkIdx * scanChunkSize
			end := min(start+scanChunkSize+int64(d.sliceByteCount)-1, fileSize)
			if err := d.scanChunk(ctx, f, fileID, window, start, end, lookupTable, matchChan); err != nil {
				d.logger.ErrorContext(ctx, "I/O error during candidate file chunk scan", "path", path, "offset", start, "err", err)
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

	// Use the candidate file's actual size for partial-block detection, since we
	// don't know a priori which protected file it corresponds to.
	return d.scanLastPartialBlock(f, fileID, fileSize, lookupTable, matchChan)
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

	h := md5.New()

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

		absPos := start + int64(j)
		atShardBoundary := absPos%int64(d.sliceByteCount) == 0

		locations, found := lookupTable.Lookup(crcSlice)
		if !found {
			if atShardBoundary {
				d.logger.DebugContext(ctx, "Shard boundary CRC miss",
					"file", sourceFileID,
					"absOffset", absPos,
					"shardIdx", absPos/int64(d.sliceByteCount),
					"viaRolling", justMissed,
					"crc", fmt.Sprintf("%08x", crcSlice))
			}
			j++
			justMissed = true
			continue
		}

		h.Reset()
		_, _ = h.Write(slice)
		var blockHash [16]byte
		copy(blockHash[:], h.Sum(nil))
		md5Matched := false
		for _, loc := range locations {
			if loc.md5Hash == blockHash {
				md5Matched = true
				matchChan <- matchEvent{
					targetFileID: loc.fileID,
					shardIndex:   loc.shardIndex,
					sourceFileID: sourceFileID,
					offset:       absPos,
				}
			}
		}

		if md5Matched {
			// True shard match: advance past this block.
			j += d.sliceByteCount
			justMissed = false
		} else {
			// CRC collision with no MD5 confirmation — treat as a miss and slide
			// one byte forward. Jumping by sliceByteCount here would skip past real
			// shard boundaries that fall in the next sliceByteCount bytes.
			if atShardBoundary {
				d.logger.DebugContext(ctx, "Shard boundary CRC hit but MD5 mismatch",
					"file", sourceFileID,
					"absOffset", absPos,
					"shardIdx", absPos/int64(d.sliceByteCount),
					"viaRolling", justMissed,
					"crc", fmt.Sprintf("%08x", crcSlice))
			}
			j++
			justMissed = true
		}
	}
	return nil
}

// Repair performs pipelined, strict memory-limited reconstruction of missing shards.
func (d *Decoder) Repair(ctx context.Context, progressChan chan<- Progress) error {
	// Phase 0: Rename misnamed files before doing any reconstruction.
	// This is much cheaper than running the RS pipeline for files that are
	// simply named differently but have identical content.
	filesRenamed := d.renameMisnamedFiles(ctx)

	counts := d.ShardCounts()
	if !counts.RepairNeeded() {
		if filesRenamed > 0 {
			d.logger.InfoContext(ctx, "All files resolved by renaming", "filesRenamed", filesRenamed)
		} else {
			d.logger.InfoContext(ctx, "No repair needed. All files are healthy.")
		}
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
	chunkSize := min(d.memoryLimit/denom, int64(d.sliceByteCount))
	chunkSize = max((chunkSize/16)*16, 16)

	d.logger.DebugContext(ctx, "Configured memory-limited streaming", "chunkSize", chunkSize, "sliceByteCount", d.sliceByteCount)

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
	for path, id := range d.candidateFiles {
		fileIDToFilename[id] = path
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

	// Log each file that will be repaired and why.
	for _, f := range d.protectedFiles {
		if !needsWrite[f.Filename] {
			continue
		}
		state := d.fileIntegrity[f.FileID]
		switch {
		case state.Missing:
			d.logger.InfoContext(ctx, "Repairing file: recreating from scratch", "file", f.Filename)
		case state.SizeMismatch:
			d.logger.InfoContext(ctx, "Repairing file: size mismatch, rewriting", "file", f.Filename)
		case state.HashMismatch:
			d.logger.InfoContext(ctx, "Repairing file: corrupt blocks, reconstructing", "file", f.Filename)
		default:
			d.logger.InfoContext(ctx, "Repairing file: blocks found in wrong location, rewriting", "file", f.Filename)
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
			if dir := filepath.Dir(name); dir != "." {
				if err = d.root.MkdirAll(dir, 0755); err != nil {
					return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
				}
			}
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
			_ = f.Close()
		}
	}()

	coder, err := rs.NewCoderPAR2Vandermonde(totalDataShards, totalParityShards)
	if err != nil {
		return err
	}

	activeDataShards := make([][]byte, totalDataShards)
	activeParityShards := make([][]byte, totalParityShards)

	// Stream data chunk by chunk
	numChunks := (int64(d.sliceByteCount) + chunkSize - 1) / chunkSize
	for chunkIdx := range numChunks {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		currChunkSize := chunkSize
		if chunkIdx == numChunks-1 {
			currChunkSize = int64(d.sliceByteCount) - (chunkIdx * chunkSize)
		}

		// 1. READER PIPELINE: Read input buffers from disk
		clear(activeDataShards)

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
				activeDataShards[i] = dataBuffers[i][:currChunkSize]
			} else {
				activeDataShards[i] = nil // nil marks missing
			}
		}

		// Read parity shards strictly aligned to their exponent matrix row slots
		clear(activeParityShards)
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
	d.logger.InfoContext(ctx, "Repair summary",
		"filesRepaired", len(needsWrite),
		"filesRenamed", filesRenamed,
		"blocksReconstructed", counts.UnusableDataShardCount)
	return nil
}

func (d *Decoder) loadVolumeFiles(ctx context.Context, indexFilename string) error {
	prefix := strings.TrimSuffix(indexFilename, ".par2")

	// Open the sandbox root directory to list files safely within the sandbox.
	dirFile, err := d.root.Open(".")
	if err != nil {
		return fmt.Errorf("failed to open sandboxed directory: %w", err)
	}
	defer func() { _ = dirFile.Close() }()

	entries, err := dirFile.ReadDir(-1)
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
	defer func() { _ = f.Close() }()

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
				d.parityFileBlocks[filename]++
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
