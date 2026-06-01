package par2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hobeone/par2engine/rs"
)

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

	plan, err := d.planRepair(ctx, filesRenamed)
	if err != nil {
		return err
	}

	// Log each file that will be repaired and why.
	for _, f := range d.protectedFiles {
		if !plan.needsWrite[f.Filename] {
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

	pipeline, err := newRepairPipeline(d, plan)
	if err != nil {
		return err
	}
	defer pipeline.close()

	// Stream data chunk by chunk
	for chunkIdx := range plan.numChunks {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err = pipeline.executeChunk(ctx, chunkIdx); err != nil {
			return err
		}

		// Report progress throttled
		if progressChan != nil {
			progressChan <- Progress{
				Phase:   "repairing",
				Current: chunkIdx + 1,
				Total:   plan.numChunks,
				Percent: float64(chunkIdx+1) / float64(plan.numChunks) * 100,
			}
		}
	}

	if err = pipeline.truncateRepairedFiles(); err != nil {
		return err
	}

	d.logger.InfoContext(ctx, "Repair completed successfully!")
	d.logger.InfoContext(ctx, "Repair summary",
		"filesRepaired", len(plan.needsWrite),
		"filesRenamed", filesRenamed,
		"blocksReconstructed", plan.counts.UnusableDataShardCount)
	return nil
}

// flattenedLocation defines a sequential record mapping parity calculation slots to their disk source and destination.
type flattenedLocation struct {
	targetFileID   FileID
	targetFilename string
	shardIndex     int
	sourceFileID   FileID
	sourceFilename string
	diskOffset     int64 // -1 if missing
}

// repairPlan captures computed sizing, mapping, and destination requirements for the repair execution.
type repairPlan struct {
	counts            ShardCounts
	totalDataShards   int
	totalParityShards int
	chunkSize         int64
	numChunks         int64
	flatLocs          []flattenedLocation
	needsWrite        map[string]bool
	filesRenamed      int
}

// planRepair verifies state, computes alignments, maps files to sequential buffers, and determines chunk bounds.
func (d *Decoder) planRepair(ctx context.Context, filesRenamed int) (*repairPlan, error) {
	if err := d.validateParityShards(); err != nil {
		return nil, err
	}

	counts := d.ShardCounts()

	totalDataShards := 0
	for _, f := range d.protectedFiles {
		totalDataShards += len(d.fileIntegrity[f.FileID].ShardLocations)
	}

	maxExp := 0
	for exp := range d.parityShards {
		if int(exp) > maxExp {
			maxExp = int(exp)
		}
	}

	chunkSize, err := d.computeChunkSize(totalDataShards, counts.UnusableDataShardCount)
	if err != nil {
		return nil, err
	}
	d.logger.DebugContext(ctx, "Configured memory-limited streaming", "chunkSize", chunkSize, "sliceByteCount", d.sliceByteCount)

	fileIDToFilename := d.buildFileIDToFilenameMap()

	return &repairPlan{
		counts:            counts,
		totalDataShards:   totalDataShards,
		totalParityShards: maxExp + 1,
		chunkSize:         chunkSize,
		numChunks:         (int64(d.sliceByteCount) + chunkSize - 1) / chunkSize,
		flatLocs:          d.buildFlatLocs(fileIDToFilename, totalDataShards),
		needsWrite:        d.buildNeedsWrite(),
		filesRenamed:      filesRenamed,
	}, nil
}

// validateParityShards guards against malicious PAR2 files whose recovery packets
// have data shorter than sliceByteCount — which passes the per-packet MD5 check
// but would panic in the chunk-offset slice expression during repair.
func (d *Decoder) validateParityShards() error {
	for exp, parityBytes := range d.parityShards {
		if len(parityBytes) != d.sliceByteCount {
			return fmt.Errorf("recovery packet exponent %d has data length %d, expected sliceByteCount %d",
				exp, len(parityBytes), d.sliceByteCount)
		}
	}
	return nil
}

// computeChunkSize returns a memory-bounded, 16-byte-aligned chunk size for streaming repair.
// The formula caps chunk size so that total buffer usage stays within d.memoryLimit:
//
//	memoryLimit ≥ chunkSize × (totalDataShards + unusableDataShards)
func (d *Decoder) computeChunkSize(totalDataShards, unusableDataShards int) (int64, error) {
	denom := int64(totalDataShards + unusableDataShards)
	if denom <= 0 {
		return 0, errors.New("invalid shard configuration for repair")
	}
	chunkSize := min(d.memoryLimit/denom, int64(d.sliceByteCount))
	return max((chunkSize/16)*16, 16), nil
}

// buildFileIDToFilenameMap returns a map from FileID to the on-disk filename,
// covering both protected files and registered candidate files.
func (d *Decoder) buildFileIDToFilenameMap() map[FileID]string {
	m := make(map[FileID]string, len(d.protectedFiles)+len(d.candidateFiles))
	for _, f := range d.protectedFiles {
		m[f.FileID] = f.Filename
	}
	for path, id := range d.candidateFiles {
		m[id] = path
	}
	return m
}

// buildFlatLocs flattens the per-file shard location map into a sequential slice
// whose indices align with the Reed-Solomon data-shard matrix rows.
func (d *Decoder) buildFlatLocs(fileIDToFilename map[FileID]string, totalDataShards int) []flattenedLocation {
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
	return flatLocs
}

// buildNeedsWrite returns the set of protected filenames that require write access
// during repair — either because they are damaged, or because their shards were
// found elsewhere (e.g., in a candidate file) and must be copied into place.
func (d *Decoder) buildNeedsWrite() map[string]bool {
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
	return needsWrite
}

// repairPipeline coordinates the reader, processor (Reed-Solomon), and writer loops for memory-bounded streaming.
type repairPipeline struct {
	d                  *Decoder
	plan               *repairPlan
	dataBuffers        [][]byte
	parityBuffers      [][]byte
	activeDataShards   [][]byte
	activeParityShards [][]byte
	coder              *rs.Coder
	openFiles          map[string]*os.File
}

func newRepairPipeline(d *Decoder, plan *repairPlan) (*repairPipeline, error) {
	dataBuffers := make([][]byte, plan.totalDataShards)
	for i := range dataBuffers {
		dataBuffers[i] = make([]byte, plan.chunkSize)
	}

	parityBuffers := make([][]byte, plan.totalParityShards)
	for i := range parityBuffers {
		parityBuffers[i] = make([]byte, plan.chunkSize)
	}

	coder, err := rs.NewCoderPAR2Vandermonde(plan.totalDataShards, plan.totalParityShards)
	if err != nil {
		return nil, err
	}

	return &repairPipeline{
		d:                  d,
		plan:               plan,
		dataBuffers:        dataBuffers,
		parityBuffers:      parityBuffers,
		activeDataShards:   make([][]byte, plan.totalDataShards),
		activeParityShards: make([][]byte, plan.totalParityShards),
		coder:              coder,
		openFiles:          make(map[string]*os.File),
	}, nil
}

func (p *repairPipeline) getFile(name string) (*os.File, error) {
	if f, ok := p.openFiles[name]; ok {
		return f, nil
	}
	var f *os.File
	var err error
	if p.plan.needsWrite[name] {
		if dir := filepath.Dir(name); dir != "." {
			if err = p.d.root.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}
		f, err = p.d.root.OpenFile(name, os.O_RDWR|os.O_CREATE, 0644)
	} else {
		f, err = p.d.root.Open(name)
	}
	if err != nil {
		return nil, err
	}
	p.openFiles[name] = f
	return f, nil
}

func (p *repairPipeline) close() {
	for _, f := range p.openFiles {
		_ = f.Close()
	}
}

func (p *repairPipeline) executeChunk(ctx context.Context, chunkIdx int64) error {
	currChunkSize := p.plan.chunkSize
	if chunkIdx == p.plan.numChunks-1 {
		currChunkSize = int64(p.d.sliceByteCount) - (chunkIdx * p.plan.chunkSize)
	}

	// 1. READER PIPELINE: Read input buffers from disk
	clear(p.activeDataShards)

	// Read present data shards relative to their offset on disk
	for i, fl := range p.plan.flatLocs {
		if fl.diskOffset != -1 {
			f, err := p.getFile(fl.sourceFilename)
			if err != nil {
				return err
			}
			offset := fl.diskOffset + (chunkIdx * p.plan.chunkSize)
			n, err := f.ReadAt(p.dataBuffers[i][:currChunkSize], offset)
			if err != nil && err != io.EOF {
				return err
			}
			// Zero out the remaining padded slice space past EOF as strictly required by the PAR2 spec!
			if n < int(currChunkSize) {
				clear(p.dataBuffers[i][n:currChunkSize])
			}
			p.activeDataShards[i] = p.dataBuffers[i][:currChunkSize]
		} else {
			p.activeDataShards[i] = nil // nil marks missing
		}
	}

	// Read parity shards strictly aligned to their exponent matrix row slots
	clear(p.activeParityShards)
	for exp, parityBytes := range p.d.parityShards {
		offset := chunkIdx * p.plan.chunkSize
		copy(p.parityBuffers[exp][:currChunkSize], parityBytes[offset:offset+currChunkSize])
		p.activeParityShards[exp] = p.parityBuffers[exp][:currChunkSize]
	}

	// 2. PROCESSOR PIPELINE: Reconstruct missing chunks concurrently
	err := p.coder.Reconstruct(ctx, p.activeDataShards, p.activeParityShards, p.d.numGoroutines)
	if err != nil {
		return err
	}

	// 3. WRITER PIPELINE: Write reconstructed chunks back to disk
	for i, fl := range p.plan.flatLocs {
		expectedOffset := int64(fl.shardIndex * p.d.sliceByteCount)
		needsCopyOrRep := fl.diskOffset == -1 || fl.sourceFileID != fl.targetFileID || fl.diskOffset != expectedOffset

		if needsCopyOrRep {
			f, err := p.getFile(fl.targetFilename)
			if err != nil {
				return err
			}
			offset := expectedOffset + (chunkIdx * p.plan.chunkSize)

			var dataToWrite []byte
			if fl.diskOffset == -1 {
				dataToWrite = p.activeDataShards[i]
			} else {
				dataToWrite = p.dataBuffers[i][:currChunkSize]
			}

			_, err = f.WriteAt(dataToWrite, offset)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (p *repairPipeline) truncateRepairedFiles() error {
	for _, fd := range p.d.protectedFiles {
		if p.plan.needsWrite[fd.Filename] { // only truncate if we actually wrote to it!
			state := p.d.fileIntegrity[fd.FileID]
			if state.Missing || state.SizeMismatch || state.HashMismatch {
				f, err := p.getFile(fd.Filename)
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
	return nil
}
