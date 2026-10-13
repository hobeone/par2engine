package par2

import (
	"bytes"
	"context"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

const fileStateSliceSize = 16384

// newFileStateSet writes a 16-block protected file "f.dat" into a fresh
// directory and creates a PAR2 set for it with par2cmdline, using
// recoveryBlocks recovery blocks. It returns the directory, the index path and
// the original bytes.
func newFileStateSet(t *testing.T, recoveryBlocks int) (dir, par2Path string, orig []byte) {
	t.Helper()
	if _, ok := hasPar2(); !ok {
		t.Skip("par2 binary not found in PATH; skipping integration test")
	}
	dir = t.TempDir()
	r := rand.New(rand.NewPCG(7, 7))
	orig = make([]byte, 16*fileStateSliceSize)
	for i := range orig {
		orig[i] = byte(r.Uint32())
	}
	if err := os.WriteFile(filepath.Join(dir, "f.dat"), orig, 0644); err != nil {
		t.Fatal(err)
	}
	par2Path = filepath.Join(dir, "set.par2")
	cmd := exec.Command("par2", "c", "-s16384", "-c"+strconv.Itoa(recoveryBlocks), par2Path, "f.dat")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to create par2 set: %v\n%s", err, out)
	}
	return dir, par2Path, orig
}

// splice returns a copy of orig with del bytes removed at offset at and ins
// inserted in their place.
func splice(orig []byte, at int, ins []byte, del int) []byte {
	out := append([]byte{}, orig[:at]...)
	out = append(out, ins...)
	return append(out, orig[at+del:]...)
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

// TestRepairRebuildsFilesWhoseBlocksAreAllLocated covers damage where every
// block of a protected file is found somewhere — shifted inside the file,
// inside another file, or followed by extra bytes — so no block is missing,
// yet the file on disk is still wrong. Repair must rebuild it rather than
// report the set healthy, and must do so without overwriting bytes that a
// later chunk still has to read from the same file.
func TestRepairRebuildsFilesWhoseBlocksAreAllLocated(t *testing.T) {
	// 64 KB over 16 data shards gives a chunk smaller than one block, so a
	// block is streamed in several chunks; the default limit gives one chunk
	// per block and cannot show the in-place overlap.
	const smallMem = 64 * 1024

	tests := []struct {
		name           string
		recoveryBlocks int
		memoryLimit    int64
		// damage mutates dir and returns any candidate files to register.
		damage func(t *testing.T, dir string, orig []byte) []string
	}{
		{
			// A stored archive holds the file's bytes at a nonzero offset, and the
			// file itself is gone: not a rename, but every block is present.
			name:           "missing_file_blocks_inside_container",
			recoveryBlocks: 4,
			damage: func(t *testing.T, dir string, orig []byte) []string {
				writeTestFile(t, filepath.Join(dir, "stored.rar"), splice(orig, 0, bytes.Repeat([]byte{0xAB}, 1000), 0))
				if err := os.Remove(filepath.Join(dir, "f.dat")); err != nil {
					t.Fatal(err)
				}
				return []string{"stored.rar"}
			},
		},
		{
			name:           "bytes_inserted_at_block_boundary",
			recoveryBlocks: 4,
			damage: func(t *testing.T, dir string, orig []byte) []string {
				writeTestFile(t, filepath.Join(dir, "f.dat"), splice(orig, 3*fileStateSliceSize, []byte("hello"), 0))
				return nil
			},
		},
		{
			name:           "bytes_inserted_at_block_boundary_small_memory",
			recoveryBlocks: 4,
			memoryLimit:    smallMem,
			damage: func(t *testing.T, dir string, orig []byte) []string {
				writeTestFile(t, filepath.Join(dir, "f.dat"), splice(orig, 3*fileStateSliceSize, bytes.Repeat([]byte{9}, 2000), 0))
				return nil
			},
		},
		{
			// Every block is located, so the rebuild is a pure reassembly and must
			// not depend on recovery blocks being present.
			name:           "bytes_inserted_no_recovery_blocks",
			recoveryBlocks: 0,
			damage: func(t *testing.T, dir string, orig []byte) []string {
				writeTestFile(t, filepath.Join(dir, "f.dat"), splice(orig, 3*fileStateSliceSize, []byte("hello"), 0))
				return nil
			},
		},
		{
			name:           "trailing_bytes_appended",
			recoveryBlocks: 4,
			damage: func(t *testing.T, dir string, orig []byte) []string {
				writeTestFile(t, filepath.Join(dir, "f.dat"), append(append([]byte{}, orig...), 1, 2, 3))
				return nil
			},
		},
		{
			// The corrupt block of f.dat is found only inside the container, so its
			// blocks come from two files and the rename path cannot apply.
			name:           "corrupt_file_with_container_candidate",
			recoveryBlocks: 4,
			damage: func(t *testing.T, dir string, orig []byte) []string {
				bad := append([]byte{}, orig...)
				bad[5*fileStateSliceSize+10] ^= 0xFF
				writeTestFile(t, filepath.Join(dir, "f.dat"), bad)
				writeTestFile(t, filepath.Join(dir, "stored.rar"), splice(orig, 0, bytes.Repeat([]byte{1}, 777), 0))
				return []string{"stored.rar"}
			},
		},
		{
			// Shard 0 is destroyed and shards 1..15 sit 2000 bytes late in the same
			// file, so repair reads and writes one file at overlapping offsets.
			name:           "in_place_shift_insert_small_memory",
			recoveryBlocks: 4,
			memoryLimit:    smallMem,
			damage: func(t *testing.T, dir string, orig []byte) []string {
				writeTestFile(t, filepath.Join(dir, "f.dat"), splice(orig, 5000, bytes.Repeat([]byte{9}, 2000), 0))
				return nil
			},
		},
		{
			name:           "in_place_shift_delete_small_memory",
			recoveryBlocks: 4,
			memoryLimit:    smallMem,
			damage: func(t *testing.T, dir string, orig []byte) []string {
				writeTestFile(t, filepath.Join(dir, "f.dat"), splice(orig, 5000, nil, 3000))
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, par2Path, orig := newFileStateSet(t, tt.recoveryBlocks)
			candidates := tt.damage(t, dir, orig)

			ctx := context.Background()
			d, err := NewDecoder(ctx, par2Path, DecoderOptions{MemoryLimit: tt.memoryLimit})
			if err != nil {
				t.Fatalf("NewDecoder failed: %v", err)
			}
			defer func() { _ = d.Close() }()
			for _, c := range candidates {
				if err := d.AddCandidateFile(c); err != nil {
					t.Fatal(err)
				}
			}

			if err := d.VerifyScans(ctx, nil); err != nil {
				t.Fatalf("VerifyScans failed: %v", err)
			}
			counts := d.ShardCounts()
			if !counts.RepairNeeded() {
				t.Fatalf("RepairNeeded() = false for a damaged file; counts=%+v", counts)
			}
			if !counts.RepairPossible() {
				t.Fatalf("RepairPossible() = false; counts=%+v", counts)
			}

			if err := d.Repair(ctx, nil); err != nil {
				t.Fatalf("Repair failed: %v", err)
			}

			got, err := os.ReadFile(filepath.Join(dir, "f.dat"))
			if err != nil {
				t.Fatalf("reading repaired file: %v", err)
			}
			if !bytes.Equal(got, orig) {
				t.Fatalf("repaired file differs from original (got %d bytes, want %d)", len(got), len(orig))
			}
			assertNoRepairTempFiles(t, dir)
		})
	}
}

// assertNoRepairTempFiles fails if a repair left a temporary file behind.
func assertNoRepairTempFiles(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*"+repairTempMarker+"*"+repairTempExt))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) > 0 {
		t.Errorf("repair left temporary files behind: %v", matches)
	}
}
