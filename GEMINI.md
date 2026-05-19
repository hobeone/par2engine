# par2engine Workspace Rules & Architecture Guidelines

Welcome, JetSki/Smith Agent. This workspace context contains a high-performance, spec-compliant, fully sandboxed PAR2 verification and repair engine written natively in Go 1.26.

When working in this repository, you **MUST** strictly adhere to the following architectural conventions, security gates, and optimization policies.

---

## 1. Architecture Overview & Package Hierarchy

- `gf16/`: Low-level Galois Field $GF(2^{16})$ field operations. Branchless, unrolled, zero-allocation.
- `rs/`: Reed-Solomon matrix arithmetic (Vandermonde / Cauchy), Gaussian row reduction, and multi-threaded parallel multiplication.
- `par2/`: Binary packets parser, sliding-window checksummer, directory sandboxing, and memory-limited pipelined repair logic.
- `cmd/gopar/`: CLI entrypoint (`par2engine-cli`).
- `tests/`: End-to-end integration tests verifying byte-for-byte compatibility against C++ `par2cmdline` archives.

---

## 2. Core Engineering Policies (Non-Negotiable)

### A. Zero-Allocation Field Math (`gf16`)
- **Performance Target**: Hot paths in `gf16` (specifically `MulByteSliceLE` and `MulAndAddByteSliceLE`) **MUST** run at zero heap allocations (`0 B/op`, `0 allocs/op`).
- **Multiplication Tables**: Do **NOT** allocate L1 multiplication tables on the heap. They must be stack-allocated (`MulTable` is a local array struct) and generated on-demand per coefficient via `CalcTable`.
- **Verification**: If you edit `gf16`, you **MUST** run benchmarks to verify throughput and allocations:
  ```bash
  go test -v -bench=. ./gf16/...
  ```

### B. Parity Shards Exponent Alignment (`rs` & `par2`)
- **Strict Spec Alignment**: The rows of the Reed-Solomon parity matrix **MUST** be strictly aligned to the mathematical exponent of the parity blocks (exponent is `0-indexed`).
- **Available Volumes Handling**: If some intermediate exponent files are missing (e.g., exponent `1` and `3` exist, but `0` and `2` are missing), the `parity` slice passed to `coder.Reconstruct` **MUST** contain `nil` elements for the missing exponents (`parity[0] = nil`, `parity[2] = nil`). Never compress them into sequential rows!

### C. Native Directory Sandboxing (`os.Root`)
- **Sycall-Enforced Isolation**: Under **NO** circumstances are you allowed to use raw `os.Open`, `os.OpenFile`, or `os.Create` for target data files. All file descriptors **MUST** be opened safely through `d.root` using the Go 1.24+ `os.Root` API.
- **Symlinks Resolution**: Since `/tmp` and `/var` are symlinked in many Unix and CI/CD environments, you **MUST** resolve the sandbox path to a canonical absolute path using `filepath.EvalSymlinks` before opening the `os.Root`.
- **Path Defanging**: PAR2 packets contain filename strings that could trigger directory traversal attacks. You **MUST** sanitize all paths:
  1. Convert all backslashes `\` to forward slashes `/`.
  2. Run `path.Clean` to strip traversal segments (`..`, `.`).
  3. Verify path is relative and does not escape the sandbox root before resolving to OS-native format via `filepath.FromSlash`.

### D. Misplaced Shard Copies & Dual Pipelining (`par2`)
- **misplaced Shards**: If a block's checksum matches, but its `diskOffset` is in the wrong file or wrong offset, `VerifyScans` records the actual source location (`loc.FileID`, `loc.Offset`).
- **Dual Processing**: The streamed `Repair` chunk loop **MUST** perform both copying and Reed-Solomon math:
  - misaligned shards must be read from their actual `sourceFilename` and written to their correct expected target offsets.
  - Missing shards must be reconstructed via `coder.Reconstruct` and written back.
- **Truncation Gate**: Repaired files **MUST** be truncated back to their exact spec size `fd.ByteCount` after writing is complete, because chunk streaming pads files to Galois 16-byte boundaries. Only truncate files that were actually written to (`needsWrite[filename] == true`) to avoid permission errors on read-only descriptors.

---

## 3. Build and Test Commands

Always run the full test suite before proposing or committing any changes:

```bash
# 1. Rebuild the CLI binary first (important for E2E integration tests)
go build -o par2engine-cli ./cmd/gopar

# 2. Run all tests in the module (unit, E2E integration, and mocks)
go test -v ./...
```

Never commit code if any tests fail. Fix all regressions first.
