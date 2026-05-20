# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build the CLI binary (required before running integration tests)
go build -o par2engine-cli ./cmd/gopar

# Run all tests (unit, integration, benchmarks)
go test -v ./...

# Run a single package's tests
go test -v ./par2/...
go test -v ./rs/...
go test -v ./gf16/...

# Run gf16 benchmarks (required after any gf16 edits to verify zero-allocation)
go test -v -bench=. ./gf16/...

# Run a single test by name
go test -v -run TestFunctionName ./par2/...
```

**Integration tests** (`tests/`) require canonical `par2cmdline` test fixture archives at `../../par2cmdline/tests/`. They skip automatically if the sibling repo is not present. The test also resolves the CLI binary at `../par2engine-cli` relative to the `tests/` directory, so rebuild the binary before running integration tests.

## Architecture

The library is structured as three layers that compose bottom-up:

```
cmd/gopar/         CLI entrypoint (verify / repair subcommands)
par2/              Core engine: packet parser, checksummer, decoder (verify + repair)
  └── rs/          Reed-Solomon erasure coder (Vandermonde matrix, Gaussian reduction)
      └── gf16/    Galois Field GF(2^16) arithmetic (zero-allocation hot paths)
tests/             E2E integration tests against par2cmdline canonical archives
```

### gf16 — Zero-Allocation Field Math

`MulTable` (1 KB) is **always stack-allocated** as a local variable inside `MulByteSliceLE` and `MulAndAddByteSliceLE`. These two functions are the hot path for all RS math. Any change that heap-allocates `MulTable` breaks the `0 B/op` performance guarantee. Verify with `go test -bench=. ./gf16/...` after any edit.

### rs — Reed-Solomon Coder

`NewCoderPAR2Vandermonde` builds a Vandermonde parity matrix using PAR2-specific generator elements. `Reconstruct` is the key entry point: it takes `data` and `parity` slices where **`nil` means missing** — do not compact missing shards into sequential rows. Parity slice indices are strictly 0-indexed exponents; `parity[exp]` must align to the mathematical exponent of that recovery block.

### par2 — Decoder Engine

`Decoder` is the top-level engine. Lifecycle: `NewDecoder` (opens sandbox + parses index) → `VerifyScans` (parallel sliding-window CRC32/MD5 scan) → `ShardCounts` (determines repair feasibility) → `Repair` (pipelined Reader-Processor-Writer loop).

Key internal types:
- `FileIntegrityState.ShardLocations` — maps `shardIndex → ShardLocation{FileID, Offset}`. `Offset == -1` means missing.
- `crcLookupTable` — hand-rolled open-addressing hash table (avoids `map` alloc overhead in the scan hot path).
- `Repair` streams data in `chunkSize`-aligned chunks (derived from `memoryLimit / totalShards`) to cap memory regardless of file size.

**All target file I/O goes through `d.root` (`os.Root`)**. Never use raw `os.Open`/`os.Create` for data files. The sandbox path is resolved via `filepath.EvalSymlinks` at construction to handle `/tmp` symlinks in CI.

## Non-Negotiable Engineering Constraints

These are correctness and security invariants — violations cause silent data corruption, security holes, or panics:

1. **gf16 zero-allocation**: `MulTable` must stay stack-allocated. Run bench after edits.

2. **Parity exponent alignment**: `parity[exp]` in `Reconstruct` calls must match the RS exponent, not be compressed sequentially. Missing exponent slots must be `nil`.

3. **Directory sandboxing**: All data file descriptors must be opened via `d.root` (Go 1.24+ `os.Root`). Use `filepath.EvalSymlinks` before opening the root.

4. **Path sanitization**: Filenames from PAR2 packets are attacker-controlled. Always run through `DefangPath` (backslash normalization → `path.Clean` → traversal check → `filepath.FromSlash`).

5. **Truncation gate**: After streamed repair, only truncate files where `needsWrite[filename] == true`. Truncating files that were not written causes permission errors on read-only descriptors.

6. **FileID sort order**: PAR2 spec requires `protectedFiles` sorted by FileID using little-endian byte comparison (last byte first). `FileIDLess` implements this — do not substitute `bytes.Compare`.

## CLI Exit Codes

Matches `par2cmdline` standard: 0=success, 1=repair possible, 2=repair not possible/failed, 3=invalid args, 4=logic error.
