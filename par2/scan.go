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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

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

// shardLocation describes the exact location of a matched shard block on disk.
type shardLocation struct {
	FileID FileID // the FileID of the physical file on disk where the block was found
	Offset int64  // byte offset in the file on disk. -1 if missing.
}

// fileIntegrityState tracks which blocks are healthy and where they are located on disk.
type fileIntegrityState struct {
	FileID         FileID
	Filename       string
	Missing        bool
	SizeMismatch   bool
	HashMismatch   bool
	Verified       bool            // true if full-file MD5 was already verified OK
	RenameSource   string          // non-empty when a candidate file is a perfect content match under a different name
	ShardLocations []shardLocation // maps expected shardIndex -> where it is actually located
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

func (d *Decoder) initFileIntegrity() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.fileIntegrity = make(map[FileID]*fileIntegrityState)
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

		locs := make([]shardLocation, shards)
		for i := range locs {
			locs[i] = shardLocation{Offset: -1}
		}
		d.fileIntegrity[f.FileID] = &fileIntegrityState{
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

	d.logFilesAndCandidates(ctx)

	if err := d.checkFileExistence(ctx); err != nil {
		return err
	}

	resolvedCandidates := d.prescanCandidateMatches(ctx)
	d.prescanProtectedMatches(ctx)

	totalBytesToScan := d.calculateBytesToScan()
	progress := d.initProgress(progressChan, totalBytesToScan)

	window, err := newCRC32Window(d.sliceByteCount)
	if err != nil {
		return err
	}

	lookupTable, err := d.buildLookupTable(ctx)
	if err != nil {
		return err
	}

	scanner := &blockScanner{
		d:                  d,
		ctx:                ctx,
		window:             window,
		sem:                make(chan struct{}, d.numGoroutines),
		lookupTable:        lookupTable,
		matchChan:          make(chan matchEvent, 100),
		progress:           progress,
		resolvedCandidates: resolvedCandidates,
	}

	if err := scanner.scan(); err != nil {
		return err
	}

	d.postScanVerify(ctx)
	return ctx.Err()
}

// logFilesAndCandidates prints the log list of protected and candidate files.
func (d *Decoder) logFilesAndCandidates(ctx context.Context) {
	// ── Phase 1: list protected files sorted alphabetically ──────────────────
	sorted := make([]FileDescPacket, len(d.protectedFiles))
	copy(sorted, d.protectedFiles)
	slices.SortFunc(sorted, func(a, b FileDescPacket) int { return strings.Compare(a.Filename, b.Filename) })
	d.logger.InfoContext(ctx, fmt.Sprintf("PAR2 set protects %d file(s):", len(sorted)))
	for _, fd := range sorted {
		d.logger.InfoContext(ctx, fmt.Sprintf("  %s (%d bytes)", fd.Filename, fd.ByteCount))
	}

	// ── Phase 3: list candidate files ────────────────────────────────────────
	if len(d.candidateFiles) > 0 {
		d.logger.InfoContext(ctx, fmt.Sprintf("Candidate file(s) to consider (%d):", len(d.candidateFiles)))
		for path := range d.candidateFiles {
			d.logger.InfoContext(ctx, fmt.Sprintf("-  %s", path))
		}
	}
}

// checkFileExistence verifies if each protected file exists, flagging them as missing if they do not.
func (d *Decoder) checkFileExistence(ctx context.Context) error {
	for _, fd := range d.protectedFiles {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f, err := d.root.Open(fd.Filename)
		if errors.Is(err, fs.ErrNotExist) {
			d.mu.Lock()
			d.fileIntegrity[fd.FileID].Missing = true
			d.mu.Unlock()
			continue
		} else if err != nil {
			return err
		}
		_ = f.Close()
	}
	return nil
}

// calculateBytesToScan returns the total size in bytes of files that need block-level scanning.
func (d *Decoder) calculateBytesToScan() int64 {
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
	return totalBytesToScan
}

// initProgress creates and initializes a progress reporting structure if needed.
func (d *Decoder) initProgress(progressChan chan<- Progress, totalBytes int64) *scanProgress {
	if progressChan == nil || totalBytes <= 0 {
		return nil
	}
	// Initial 0% progress update
	progressChan <- Progress{
		Phase:   "verifying",
		Current: 0,
		Total:   totalBytes,
		Percent: 0.0,
	}
	return &scanProgress{
		totalBytes:   totalBytes,
		progressChan: progressChan,
	}
}

// buildLookupTable constructs an open-addressing CRC lookup table from IFSC packets.
func (d *Decoder) buildLookupTable(ctx context.Context) (*crcLookupTable, error) {
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
	return newCRCLookupTable(checksumMap), nil
}

// blockScanner orchestrates block-level sliding window CRC & MD5 verification.
type blockScanner struct {
	d                  *Decoder
	ctx                context.Context
	window             *crc32Window
	sem                chan struct{}
	lookupTable        *crcLookupTable
	matchChan          chan matchEvent
	progress           *scanProgress
	scanWg             sync.WaitGroup
	scanErr            error
	scanErrMu          sync.Mutex
	resolvedCandidates map[string]bool
}

func (s *blockScanner) setScanErr(err error) {
	s.scanErrMu.Lock()
	defer s.scanErrMu.Unlock()
	if s.scanErr == nil {
		s.scanErr = err
	}
}

func (s *blockScanner) scan() error {
	var collectorWg sync.WaitGroup
	collectorWg.Go(func() {
		for match := range s.matchChan {
			s.d.mu.Lock()
			state := s.d.fileIntegrity[match.targetFileID]
			if state.ShardLocations[match.shardIndex].Offset == -1 {
				s.d.logger.Debug("Block match found",
					"targetFile", state.Filename,
					"shardIdx", match.shardIndex,
					"sourceFileID", fmt.Sprintf("%x", match.sourceFileID[:4]),
					"offset", match.offset)
				state.ShardLocations[match.shardIndex] = shardLocation{
					FileID: match.sourceFileID,
					Offset: match.offset,
				}
			}
			s.d.mu.Unlock()
		}
	})

	// Scan protected files that exist on disk and are not already pre-verified.
	for _, fDesc := range s.d.protectedFiles {
		if s.ctx.Err() != nil {
			break
		}
		s.d.mu.Lock()
		state := s.d.fileIntegrity[fDesc.FileID]
		missing := state.Missing
		verified := state.Verified
		s.d.mu.Unlock()
		if missing || verified {
			continue
		}
		s.scanWg.Go(func() {
			if err := s.scanFile(fDesc); err != nil {
				s.d.logger.ErrorContext(s.ctx, "failed to scan file", "file", fDesc.Filename, "err", err)
				s.setScanErr(err)
			}
		})
	}

	// Scan candidate files not already resolved by the pre-scan phase.
	protectedNames := make(map[string]bool, len(s.d.protectedFiles))
	for _, fd := range s.d.protectedFiles {
		protectedNames[fd.Filename] = true
	}
	for path, fileID := range s.d.candidateFiles {
		if s.ctx.Err() != nil {
			break
		}
		if s.resolvedCandidates[path] || protectedNames[path] {
			continue
		}
		s.scanWg.Go(func() {
			if err := s.scanCandidateFile(path, fileID); err != nil {
				s.d.logger.ErrorContext(s.ctx, "failed to scan candidate file", "path", path, "err", err)
				s.setScanErr(err)
			}
		})
	}

	s.scanWg.Wait()
	close(s.matchChan)
	collectorWg.Wait()

	return s.scanErr
}

// postScanVerify runs the post-scan MD5 hash verification phase: for each
// protected file it checks whether the file hash is correct, detects rename
// candidates, then logs per-file status and an overall verification summary.
//
// Lock discipline: acquires d.mu at entry, releases/re-acquires it for I/O,
// and releases it on return. detectRenameCandidate must be called under the lock
// (it drops/re-acquires internally for its own I/O).
// Compute ShardCounts inline rather than calling d.ShardCounts() to avoid deadlock.
func (d *Decoder) postScanVerify(ctx context.Context) {
	d.logger.DebugContext(ctx, "Starting post-scan MD5 hash verification phase")

	d.mu.Lock()
	d.verifyProtectedFilesHashes(ctx)

	// Compute final shard tallies while still holding the lock — calling d.ShardCounts() here
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
	d.mu.Unlock()

	finalCounts := ShardCounts{
		UsableDataShardCount:   usableData,
		UnusableDataShardCount: unusableData,
		UsableParityShardCount: len(d.parityShards),
		RenamesNeeded:          renamesNeeded,
	}

	d.logVerificationReport(ctx, finalCounts)
}

// verifyProtectedFilesHashes iterates over protected files and verifies their integrity.
// Assumes d.mu is held.
func (d *Decoder) verifyProtectedFilesHashes(ctx context.Context) {
	for _, fd := range d.protectedFiles {
		state := d.fileIntegrity[fd.FileID]
		if state.Verified || state.SizeMismatch {
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

		if d.isAllShardsConsecutive(fd, state) {
			// Standard full file MD5 check — unlock while doing I/O to avoid holding
			// the mutex across potentially slow disk reads.
			d.mu.Unlock()
			d.verifySingleFileHash(ctx, fd, state)
			d.mu.Lock()
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
}

// isAllShardsConsecutive checks if all shards of a protected file are located at their expected consecutive offsets.
// Assumes d.mu is held.
func (d *Decoder) isAllShardsConsecutive(fd FileDescPacket, state *fileIntegrityState) bool {
	for idx, loc := range state.ShardLocations {
		expected := int64(idx * d.sliceByteCount)
		if loc.Offset != expected || loc.FileID != fd.FileID {
			return false
		}
	}
	return true
}

// verifySingleFileHash opens the file, computes its full MD5 checksum, and compares it against expected.
// It assumes d.mu is NOT held when doing I/O.
func (d *Decoder) verifySingleFileHash(ctx context.Context, fd FileDescPacket, state *fileIntegrityState) {
	d.logger.DebugContext(ctx, "Running MD5 hash check", "file", fd.Filename)
	f, err := d.root.Open(fd.Filename)
	if err != nil {
		d.mu.Lock()
		state.Missing = true
		d.mu.Unlock()
		return
	}
	defer func() { _ = f.Close() }()

	hasher := md5.New()
	_, copyErr := io.Copy(hasher, f)
	if copyErr != nil {
		d.logger.WarnContext(ctx, "I/O error during MD5 verification", "file", fd.Filename, "err", copyErr)
		d.mu.Lock()
		state.HashMismatch = true
		d.mu.Unlock()
		return
	}

	var fileHash [16]byte
	copy(fileHash[:], hasher.Sum(nil))

	d.mu.Lock()
	defer d.mu.Unlock()
	if fileHash != fd.Hash {
		d.logger.WarnContext(ctx, "File hash verification FAILED",
			"file", fd.Filename,
			"expected", fmt.Sprintf("%x", fd.Hash),
			"actual", fmt.Sprintf("%x", fileHash))
		state.HashMismatch = true
	} else {
		d.logger.DebugContext(ctx, "File hash verified OK", "file", fd.Filename)
		state.Verified = true
		state.Missing = false
		state.SizeMismatch = false
		state.HashMismatch = false
	}
}

// logVerificationReport logs the final per-file status and summary of verification.
// Assumes d.mu is NOT held.
func (d *Decoder) logVerificationReport(ctx context.Context, finalCounts ShardCounts) {
	d.logger.DebugContext(ctx, "Post-scan complete",
		"usableDataShards", finalCounts.UsableDataShardCount,
		"unusableDataShards", finalCounts.UnusableDataShardCount,
		"usableParityShards", finalCounts.UsableParityShardCount)

	okCount, missingCount, damagedCount, renameCount := 0, 0, 0, 0
	d.mu.Lock()
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
}

// quickHashSize is the number of bytes hashed as the fast pre-filter in both prescan methods.
const quickHashSize = 16 * 1024

// quickHash16K reads up to the first 16 KB of f and returns the MD5 of those bytes.
// Returns an error on I/O failures other than EOF.
func quickHash16K(f *os.File, fileSize int64) ([16]byte, error) {
	buf := make([]byte, min(quickHashSize, int(fileSize)))
	n, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return [16]byte{}, err
	}
	return md5.Sum(buf[:n]), nil
}

// computeFileMD5 seeks f to the beginning and returns the MD5 of the entire file.
func computeFileMD5(f *os.File) ([16]byte, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return [16]byte{}, err
	}
	hasher := md5.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return [16]byte{}, err
	}
	var h [16]byte
	copy(h[:], hasher.Sum(nil))
	return h, nil
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

		quickHash, err := quickHash16K(f, fileSize)
		if err != nil {
			_ = f.Close()
			continue
		}

		fd, ok := missingByQuickKey[quickKey{fileSize, quickHash}]
		if !ok {
			_ = f.Close()
			continue
		}

		// 16 KB matched — compute full-file MD5 to confirm.
		d.logger.InfoContext(ctx, "Pre-verifying candidate file...", "candidate", candidatePath, "matchedFile", fd.Filename, "size", fileSize)
		fullHash, err := computeFileMD5(f)
		_ = f.Close()
		if err != nil {
			continue
		}
		if fullHash != fd.Hash {
			continue
		}

		// Perfect match: populate ShardLocations and mark for rename.
		d.mu.Lock()
		state := d.fileIntegrity[fd.FileID]
		state.RenameSource = candidatePath
		state.Verified = true
		for i := range state.ShardLocations {
			state.ShardLocations[i] = shardLocation{
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

		quickHash, err := quickHash16K(f, fileSize)
		if err != nil {
			_ = f.Close()
			continue
		}
		if quickHash != fd.SixteenKHash {
			_ = f.Close()
			continue
		}

		// 16 KB matched — compute full-file MD5 to confirm.
		d.logger.InfoContext(ctx, "Pre-verifying file...", "file", fd.Filename, "size", fileSize)
		fullHash, err := computeFileMD5(f)
		_ = f.Close()
		if err != nil {
			continue
		}
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
			state.ShardLocations[idx] = shardLocation{
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
func (d *Decoder) detectRenameCandidate(ctx context.Context, fd FileDescPacket, state *fileIntegrityState) string {
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

	// Look up the candidate path via the reverse index — O(1) instead of O(n).
	candidatePath := d.candidateByID[candidateID]
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
			state.ShardLocations[idx] = shardLocation{
				FileID: fd.FileID,
				Offset: int64(idx * d.sliceByteCount),
			}
		}
		renamed++
	}
	return renamed
}

// scanChunkSize is the unit of parallel I/O during the sliding-window scan.
const scanChunkSize = 32 * 1024 * 1024

func (s *blockScanner) scanFile(fd FileDescPacket) error {
	f, err := s.d.root.Open(fd.Filename)
	if errors.Is(err, fs.ErrNotExist) {
		// Phase 4 of VerifyScans already logged and set Missing — nothing to do here.
		s.d.mu.Lock()
		s.d.fileIntegrity[fd.FileID].Missing = true
		s.d.mu.Unlock()
		return nil
	} else if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return err
	}

	s.d.mu.Lock()
	state := s.d.fileIntegrity[fd.FileID]
	if stat.Size() != int64(fd.ByteCount) {
		s.d.logger.Warn("File size mismatch", "file", fd.Filename, "expected", fd.ByteCount, "actual", stat.Size())
		state.SizeMismatch = true
	}
	s.d.mu.Unlock()

	fileSize := stat.Size()
	if fileSize == 0 {
		return nil
	}

	if err := s.scanFileChunks(f, fd.FileID, fd.Filename, fileSize); err != nil {
		return err
	}
	return s.scanLastPartialBlock(f, fd.FileID, int64(fd.ByteCount))
}

// scanFileChunks divides f into scanChunkSize-aligned parallel chunks and runs
// the sliding-window CRC scan on each. name is used only for error log messages.
func (s *blockScanner) scanFileChunks(f *os.File, sourceFileID FileID, name string, fileSize int64) error {
	var wg sync.WaitGroup
	var chunkErr error
	var chunkErrMu sync.Mutex

	numChunks := (fileSize + scanChunkSize - 1) / scanChunkSize
	for i := range numChunks {
		if s.ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(chunkIdx int64) {
			defer wg.Done()

			// Throttle concurrency at the chunk level to respect memory limits.
			select {
			case s.sem <- struct{}{}:
			case <-s.ctx.Done():
				return
			}
			defer func() { <-s.sem }()

			start := chunkIdx * scanChunkSize
			end := min(start+scanChunkSize+int64(s.d.sliceByteCount)-1, fileSize)

			if err := s.scanChunk(f, sourceFileID, start, end); err != nil {
				s.d.logger.ErrorContext(s.ctx, "I/O error during chunk scan", "name", name, "offset", start, "err", err)
				chunkErrMu.Lock()
				if chunkErr == nil {
					chunkErr = err
				}
				chunkErrMu.Unlock()
			} else {
				s.progress.add(min(scanChunkSize, fileSize-start))
			}
		}(i)
	}

	wg.Wait()
	return chunkErr
}

// scanLastPartialBlock checks the final block of a file when its size is not a
// multiple of sliceByteCount. The block is zero-padded to sliceByteCount before
// hashing, matching the PAR2 specification.
func (s *blockScanner) scanLastPartialBlock(f *os.File, sourceFileID FileID, byteCount int64) error {
	if uint64(byteCount)%uint64(s.d.sliceByteCount) == 0 {
		return nil
	}
	shards := (uint64(byteCount) + uint64(s.d.sliceByteCount) - 1) / uint64(s.d.sliceByteCount)
	lastBlockStart := int64((shards - 1) * uint64(s.d.sliceByteCount))
	lastBlockLen := byteCount - lastBlockStart

	paddedBlock := make([]byte, s.d.sliceByteCount)
	if _, err := f.ReadAt(paddedBlock[:lastBlockLen], lastBlockStart); err != nil && err != io.EOF {
		return err
	}

	crcVal := crc32.ChecksumIEEE(paddedBlock)
	if locations, found := s.lookupTable.Lookup(crcVal); found {
		blockHash := md5.Sum(paddedBlock)
		for _, loc := range locations {
			if loc.md5Hash == blockHash {
				s.matchChan <- matchEvent{
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
func (s *blockScanner) scanCandidateFile(path string, fileID FileID) error {
	f, err := s.d.root.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		s.d.logger.WarnContext(s.ctx, "candidate file not found, skipping", "path", path)
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

	if err := s.scanFileChunks(f, fileID, path, fileSize); err != nil {
		return err
	}
	// Use the candidate file's actual size for partial-block detection, since we
	// don't know a priori which protected file it corresponds to.
	return s.scanLastPartialBlock(f, fileID, fileSize)
}

func (s *blockScanner) scanChunk(f *os.File, sourceFileID FileID, start, end int64) error {
	bufferSize := end - start
	if bufferSize < int64(s.d.sliceByteCount) {
		return nil
	}
	data := make([]byte, bufferSize)
	_, err := f.ReadAt(data, start)
	if err != nil && err != io.EOF {
		return fmt.Errorf("ReadAt offset %d: %w", start, err)
	}

	h := md5.New()
	sumBuf := make([]byte, 0, 16)

	var crcSlice uint32
	justMissed := false

	for j := 0; j <= len(data)-s.d.sliceByteCount; {
		// Only check context cancellation once every 65,536 bytes to eliminate atomic lock overheads in tight loops
		if j&0xFFFF == 0 {
			if s.ctx.Err() != nil {
				return nil
			}
		}

		slice := data[j : j+s.d.sliceByteCount]
		if justMissed {
			crcSlice = s.window.update(crcSlice, data[j-1], slice[len(slice)-1])
		} else {
			crcSlice = crc32.ChecksumIEEE(slice)
		}

		absPos := start + int64(j)
		atShardBoundary := absPos%int64(s.d.sliceByteCount) == 0

		locations, found := s.lookupTable.Lookup(crcSlice)
		if !found {
			if atShardBoundary {
				s.d.logger.DebugContext(s.ctx, "Shard boundary CRC miss",
					"file", sourceFileID,
					"absOffset", absPos,
					"shardIdx", absPos/int64(s.d.sliceByteCount),
					"viaRolling", justMissed,
					"crc", fmt.Sprintf("%08x", crcSlice))
			}
			j++
			justMissed = true
			continue
		}

		h.Reset()
		_, _ = h.Write(slice)
		sumBuf = h.Sum(sumBuf[:0])
		var blockHash [16]byte
		copy(blockHash[:], sumBuf)
		md5Matched := false
		for _, loc := range locations {
			if loc.md5Hash == blockHash {
				md5Matched = true
				s.matchChan <- matchEvent{
					targetFileID: loc.fileID,
					shardIndex:   loc.shardIndex,
					sourceFileID: sourceFileID,
					offset:       absPos,
				}
			}
		}

		if md5Matched {
			// True shard match: advance past this block.
			j += s.d.sliceByteCount
			justMissed = false
		} else {
			// CRC collision with no MD5 confirmation — treat as a miss and slide
			// one byte forward. Jumping by sliceByteCount here would skip past real
			// shard boundaries that fall in the next sliceByteCount bytes.
			if atShardBoundary {
				s.d.logger.DebugContext(s.ctx, "Shard boundary CRC hit but MD5 mismatch",
					"file", sourceFileID,
					"absOffset", absPos,
					"shardIdx", absPos/int64(s.d.sliceByteCount),
					"viaRolling", justMissed,
					"crc", fmt.Sprintf("%08x", crcSlice))
			}
			j++
			justMissed = true
		}
	}
	return nil
}
