# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build the CLI binary
go build -o par2engine-cli ./cmd/gopar

# Run all tests (unit, integration, benchmarks)
go test -v ./...

# Run a single package's tests
go test -v ./par2/...
go test -v ./rs/...
go test -v ./gf16/...

# Assert the zero-allocation guarantee (must not run under -race; see below)
go test -run ZeroAlloc ./gf16/...

# Run gf16 benchmarks to see throughput numbers after any gf16 edits
go test -v -bench=. ./gf16/...

# Regenerate the avo-produced AVX2 assembly after editing gf16/asm.go
go generate ./gf16/...

# Run a single test by name
go test -v -run TestFunctionName ./par2/...
```

**Integration tests** (`tests/`) are self-sufficient — `TestMain` resolves the canonical `par2cmdline` fixture archives in three steps: the `tests/testdata/` cache from a previous run, then a sibling clone at `../../par2cmdline/tests/`, then downloading them from `parchive/par2cmdline` into `tests/testdata/`. It also builds the CLI at `../par2engine-cli` itself if that binary is absent, so no separate build step is needed first. The only external requirement is network access on the first run.

**CI** (`.github/workflows/ci.yml`) runs build/vet/`-race` tests, the zero-allocation assertions, golangci-lint, a generated-assembly drift check, the integration suite, and cross-compile builds for 386/arm/arm64/darwin-arm64/windows.

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

The 1 KB `mulTable` is **always stack-allocated**, as a local variable inside `mulScalarByteSliceLE` and `mulAndAddScalarByteSliceLE` (`gf16.go`) — the scalar path that the exported `MulByteSliceLE` and `MulAndAddByteSliceLE` delegate to. Those two exported functions are the hot path for all RS math. Any change that heap-allocates `mulTable` breaks the `0 B/op` performance guarantee.

`TestMulByteSliceLEZeroAlloc` / `TestMulAndAddByteSliceLEZeroAlloc` (`gf16_alloc_test.go`) assert this and run in CI. Two things about them are load-bearing:

- On amd64 with AVX2, any length that is a whole multiple of 64 dispatches straight to the assembly kernel and **never reaches the scalar path**. The tests therefore cover unaligned sizes too; a test using only aligned buffers would pass while measuring nothing.
- They carry a `//go:build !race` constraint, because the race detector allocates for its own instrumentation. Run them without `-race`.

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

1. **gf16 zero-allocation**: `mulTable` must stay stack-allocated. Verified by `go test -run ZeroAlloc ./gf16/...` (without `-race`), which CI enforces.

2. **Parity exponent alignment**: `parity[exp]` in `Reconstruct` calls must match the RS exponent, not be compressed sequentially. Missing exponent slots must be `nil`.

3. **Directory sandboxing**: All data file descriptors must be opened via `d.root` (Go 1.24+ `os.Root`). Use `filepath.EvalSymlinks` before opening the root.

4. **Path sanitization**: Filenames from PAR2 packets are attacker-controlled. Always run through `DefangPath` (backslash normalization → `path.Clean` → traversal check → `filepath.FromSlash`).

5. **Truncation gate**: After streamed repair, only truncate files where `needsWrite[filename] == true`. Truncating files that were not written causes permission errors on read-only descriptors.

6. **FileID sort order**: PAR2 spec requires `protectedFiles` sorted by FileID using little-endian byte comparison (last byte first). `FileIDLess` implements this — do not substitute `bytes.Compare`.

## CLI Exit Codes

Matches `par2cmdline` standard: 0=success, 1=repair possible, 2=repair not possible/failed, 3=invalid args, 4=logic error.
