# par2engine Workspace Rules & Architecture Guidelines

This workspace contains a high-performance, spec-compliant, fully sandboxed PAR2 verification and repair engine written natively in Go 1.26.

When working in this repository, you **MUST** strictly adhere to the following architectural conventions, security gates, and optimization policies.

---

## 1. Architecture Overview & Package Hierarchy

The library is structured as three layers that compose bottom-up:

```
cmd/gopar/         CLI entrypoint (verify / repair subcommands)
par2/              Core engine: packet parser, checksummer, decoder (verify + repair)
  └── rs/          Reed-Solomon erasure coder (Vandermonde matrix, Gaussian reduction)
      └── gf16/    Galois Field GF(2^16) arithmetic (zero-allocation hot paths)
tests/             E2E integration tests against par2cmdline canonical archives
```

### gf16 — Zero-Allocation Field Math
- **Performance Target**: Hot paths in `gf16` (specifically `MulByteSliceLE` and `MulAndAddByteSliceLE`) **MUST** run at zero heap allocations (`0 B/op`, `0 allocs/op`).
- **Multiplication Tables**: Do **NOT** allocate L1 multiplication tables on the heap. They must be stack-allocated (`MulTable` is a local array struct of 1 KB) inside the hot path functions and generated on-demand per coefficient via `CalcTable`.
- **Verification**: If you edit `gf16`, you **MUST** run benchmarks to verify throughput and allocations:
  ```bash
  go test -v -bench=. ./gf16/...
  ```

### rs — Reed-Solomon Coder
- **Strict Spec Alignment**: The rows of the Reed-Solomon parity matrix **MUST** be strictly aligned to the mathematical exponent of the parity blocks (exponent is `0-indexed`).
- **Available Volumes Handling**: If some intermediate exponent files are missing (e.g., exponent `1` and `3` exist, but `0` and `2` are missing), the `parity` slice passed to `coder.Reconstruct` **MUST** contain `nil` elements for the missing exponents (`parity[0] = nil`, `parity[2] = nil`). Never compress them into sequential rows!

### par2 — Decoder Engine
`Decoder` is the top-level engine. Lifecycle: `NewDecoder` (opens sandbox + parses index) → `VerifyScans` (parallel sliding-window CRC32/MD5 scan) → `ShardCounts` (determines repair feasibility) → `Repair` (pipelined Reader-Processor-Writer loop).

Key internal design details:
- **FileIntegrityState.ShardLocations**: Maps `shardIndex → ShardLocation{FileID, Offset}`. `Offset == -1` means missing.
- **crcLookupTable**: Hand-rolled open-addressing hash table (avoids map allocation overhead in the scan hot path).
- **Dual Processing**: The streamed `Repair` chunk loop **MUST** perform both copying and Reed-Solomon math:
  - Misaligned shards must be read from their actual `sourceFilename` and written to their correct expected target offsets.
  - Missing shards must be reconstructed via `coder.Reconstruct` and written back.
- **Memory Caps**: `Repair` streams data in `chunkSize`-aligned chunks (derived from `memoryLimit / totalShards`) to cap memory regardless of file size.

---

## 2. Non-Negotiable Engineering Constraints

These are correctness and security invariants — violations cause silent data corruption, security holes, or panics:

1. **gf16 zero-allocation**: `MulTable` must stay stack-allocated inside `MulByteSliceLE` and `MulAndAddByteSliceLE`. Run benchmarks after any edits to verify `0 B/op`.
2. **Parity exponent alignment**: `parity[exp]` in `Reconstruct` calls must match the RS exponent, not be compressed sequentially. Missing exponent slots must be `nil`.
3. **Directory sandboxing**: Under **NO** circumstances use raw `os.Open`, `os.OpenFile`, or `os.Create` for target data files. All file descriptors **MUST** be opened safely through `d.root` using the Go 1.24+ `os.Root` API. The sandbox path must be resolved to a canonical absolute path using `filepath.EvalSymlinks` before opening `os.Root` to handle symlinked directories (e.g., `/tmp` or `/var`).
4. **Path sanitization**: Filenames from PAR2 packets are attacker-controlled and can trigger directory traversal attacks. You **MUST** sanitize all paths through `DefangPath`:
   1. Convert all backslashes `\` to forward slashes `/`.
   2. Run `path.Clean` to strip traversal segments (`..`, `.`).
   3. Verify path is relative and does not escape the sandbox root before resolving to OS-native format via `filepath.FromSlash`.
5. **Truncation gate**: After streamed repair, repaired files **MUST** be truncated back to their exact spec size `fd.ByteCount` after writing is complete (since chunk streaming pads files to Galois 16-byte boundaries). Only truncate files that were actually written to (`needsWrite[filename] == true`) to avoid permission errors on read-only descriptors.
6. **FileID sort order**: The PAR2 spec requires `protectedFiles` sorted by FileID using little-endian byte comparison (last byte first). `FileIDLess` implements this — do not substitute `bytes.Compare` or standard lexicographical sort.

---

## 3. Build and Test Commands

Always run the full test suite before proposing or committing any changes:

```bash
# 1. Rebuild the CLI binary first (important for E2E integration tests)
go build -o par2engine-cli ./cmd/gopar

# 2. Run all tests in the module (unit, E2E integration, and mocks)
go test -v ./...

# 3. Run a single package's tests
go test -v ./par2/...
go test -v ./rs/...
go test -v ./gf16/...

# 4. Run gf16 benchmarks (verify zero-allocation)
go test -v -bench=. ./gf16/...
```

**Integration tests** (`tests/`) require canonical `par2cmdline` test fixture archives at `../../par2cmdline/tests/`. They skip automatically if the sibling repo is not present. The E2E tests resolve the CLI binary at `../par2engine-cli` relative to the `tests/` directory, so rebuild the binary before running integration tests.

---

## 4. CLI Exit Codes

Matches `par2cmdline` standard:
- `0`: Success (verification or repair successful)
- `1`: Repair possible (but not yet run)
- `2`: Repair not possible / failed
- `3`: Invalid arguments
- `4`: Logic / runtime error

---

## Development Standards

Any developer working on this codebase **must** follow these mandates.

### Tooling Setup

```bash
# Install goimports if not present
go install golang.org/x/tools/cmd/goimports@latest

# Install golangci-lint if not present (see https://golangci-lint.run/welcome/install/)
```

### Per-File Workflow (after every .go file edit)

```bash
goimports -w <file>   # format + resolve imports
go fix ./...          # adopt new language features automatically
go build ./...        # verify it compiles
```

### Quality Gate (before every commit)

```bash
goimports -w .
go fix ./...
go vet ./...
go test -race ./...
golangci-lint run ./...
```

All five must pass. Do not commit with failing tests, vet errors, or lint warnings.

### Coding Standards

- **Idioms:** "Accept interfaces, return structs." Define interfaces at the consumer side.
- **Context:** Every blocking or cancellable operation **must** accept `context.Context` as the first parameter.
- **Errors:** Wrap with `fmt.Errorf("component: ...: %w", err)`. Never use `%v` for errors that will be inspected.
- **No hacks:** No `init()` for setup. No `panic` for control flow. No `time.Sleep` in tests — use channels or `sync.WaitGroup`.
- **Standard library first:** Prefer `slices`, `maps`, `errors.Is/As`, `min`/`max` builtins over custom helpers or reflection.

### Concurrency & Locking

- **Never hold a mutex during I/O.** Snapshot under the lock, release, then do I/O.
- **Always `defer mu.Unlock()`.** Only exception: intentional snapshot-then-release, marked with `// --- no lock held below this line ---`.
- **Every `select` must watch `ctx.Done()`.** Goroutines blocked without a context escape route leak forever.
- **Use `sync.Once` or `CompareAndSwap` for idempotent shutdown.** Prevents double-close panics.

### Commit Convention

All commits must follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>
```

| Type | When to use |
|------|-------------|
| `feat` | New user-visible capability |
| `fix` | Bug patch |
| `perf` | Performance improvement with benchmark evidence |
| `refactor` | Code restructuring, no behavior change |
| `test` | Adding or improving tests |
| `docs` | Documentation only |
| `chore` | Build, CI, dependency updates |

Append `!` or add `BREAKING CHANGE:` footer for any public API or wire-format change.
