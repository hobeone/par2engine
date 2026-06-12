package par2

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
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

	root *os.Root // sandboxed target folder directory root (Go 1.24+)

	sliceByteCount int
	recoverySetID  [16]byte
	protectedFiles []FileDescPacket
	fileChecksums  map[FileID]*IFSCPacket
	parityShards   map[uint16][]byte // exponent -> parity bytes loaded from par2 files

	fileIntegrity    map[FileID]*fileIntegrityState
	candidateFiles   map[string]FileID // extra files to scan; path → synthetic FileID
	candidateByID    map[FileID]string // reverse of candidateFiles: FileID → path
	parityFileBlocks map[string]int    // par2 filename → number of recovery blocks it contributes
	mu               sync.Mutex        // protects shared state updates
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

	root, err := openSandbox(dir)
	if err != nil {
		return nil, err
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
		fileIntegrity:    make(map[FileID]*fileIntegrityState),
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

// openSandbox Canonicalizes and sandboxes a directory using os.OpenRoot.
func openSandbox(dir string) (*os.Root, error) {
	absDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve canonical path: %w", err)
	}
	root, err := os.OpenRoot(absDir)
	if err != nil {
		return nil, fmt.Errorf("failed to sandbox target directory: %w", err)
	}
	return root, nil
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
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.candidateFiles == nil {
		d.candidateFiles = make(map[string]FileID)
		d.candidateByID = make(map[FileID]string)
	}
	if _, exists := d.candidateFiles[defanged]; !exists {
		// Synthetic FileID: deterministic hash that won't collide with real PAR2
		// FileIDs (which are MD5 of 16KHash ‖ byteCount ‖ filename).
		id := FileID(md5.Sum([]byte("candidate:" + defanged)))
		d.candidateFiles[defanged] = id
		d.candidateByID[id] = defanged
	}
	return nil
}

func (d *Decoder) loadIndexFile(ctx context.Context, indexFilename string) error {
	d.logger.InfoContext(ctx, "Loading index PAR2 file", "file", indexFilename)

	err := d.streamPAR2Packets(ctx, indexFilename, func(h Header, body []byte) error {
		return d.handlePacket(ctx, h, body, indexFilename)
	})
	if err != nil {
		return err
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

// streamPAR2Packets streams PAR2 packets from a file relative to sandbox root,
// performing standard boundary validation, security checks, hash verification,
// and recovery set ID alignment checks before invoking the handler.
func (d *Decoder) streamPAR2Packets(ctx context.Context, filename string, handle func(h Header, body []byte) error) error {
	f, err := d.root.Open(filename)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	if stat.Size() > d.maxFileSize {
		return fmt.Errorf("file %s exceeds maximum allowed size (%d bytes > %d byte limit)", filename, stat.Size(), d.maxFileSize)
	}

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
			return errors.New("corrupt packet hash mismatch")
		}

		// If this is the very first packet of the index file, initialize recoverySetID.
		// Otherwise, enforce alignment across all packets in all files.
		if d.recoverySetID == [16]byte{} {
			d.recoverySetID = h.RecoverySetID
		} else if h.RecoverySetID != d.recoverySetID {
			d.logger.Warn("skipping packet with mismatching set ID")
			continue
		}

		if err = handle(h, body); err != nil {
			return err
		}
	}

	return nil
}

// handlePacket dispatches and decodes individual PAR2 packets of different types.
func (d *Decoder) handlePacket(ctx context.Context, h Header, body []byte, filename string) error {
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
		if p == nil {
			// 0-byte file: no blocks to verify or repair; skip per PAR2 spec.
			if len(body) >= 56 {
				d.logger.DebugContext(ctx, "skipping 0-byte file in PAR2 index",
					"file", DecodeNullPaddedASCIIString(body[56:]))
			}
			return nil
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
			d.parityFileBlocks[filename]++
		}
	}
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
	err := d.streamPAR2Packets(ctx, filename, func(h Header, body []byte) error {
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
		return nil
	})
	if err != nil {
		return err
	}

	d.mu.Lock()
	blocks := d.parityFileBlocks[filename]
	d.mu.Unlock()
	d.logger.InfoContext(ctx, "Loaded recovery volume file", "file", filename, "recoveryBlocks", blocks)

	return nil
}
