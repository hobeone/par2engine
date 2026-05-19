# par2engine

A high-performance, spec-compliant, and fully sandboxed PAR2 validation and repair library written natively in Go 1.26.

## Features

- **Zero-Allocation Galois Field Math (`gf16`)**: Custom stack-allocated $1KB$ L1-cached multiplication tables generated on-demand, unrolled loops, and branchless field arithmetic achieving **`~1.5 GB/s` throughput** with `0 B/op`.
- **Reed-Solomon Coding (`rs`)**: Multi-threaded Vandermonde erasure coding mapping matrix rows to exponents. Supports Cauchy matrices, Gaussian row reduction, and zero-allocation slice conversions via `unsafe.Slice`.
- **Complete PAR2 Packet Parser (`par2`)**: Handles Main, File Description, IFSC, and Recovery packets. Formulates strict sorted file list order compliant with PAR2 standard specifications.
- **Native OS-Level Sandboxing (`os.Root`)**: Uses Go 1.24+'s new `os.Root` directory descriptors. Bypasses `/tmp` symbolic link bugs with `filepath.EvalSymlinks` and blocks all path traversal attempts at the kernel syscall level.
- **Parallel Scanning & misplaced Shards**: Sliding-window rolling CRC32/MD5 verification processes single large files in parallel using lock-free collector queues. Re-aligns misplaced shards found in other files.
- **Memory-Limited Streamed Repair**: Reader-Processor-Writer concurrent pipelining streams blocks in small Galois-aligned chunks, capping memory consumption to user limits (e.g. 16MB) regardless of file sizes.
- **Real-Time Updates**: Out-of-the-box throttled `Progress` channel integration and structured `slog.Logger` callbacks.

---

## Getting Started

### Installation
Import the library in your Go project:
```go
import "github.com/hobeone/par2engine/par2"
```

### CLI Tool Usage
A small, optimized CLI tool is included in `cmd/gopar`:

```bash
# Build the CLI
go build -o par2engine-cli ./cmd/gopar

# Verify files against a PAR2 set
./par2engine-cli verify /path/to/set.par2

# Repair corrupted or missing files
./par2engine-cli -t 4 -m 32 repair /path/to/set.par2
```

### CLI Flags
- `-t <n>`: Number of concurrent processing threads (defaults to physical CPU cores).
- `-m <n>`: Memory limit in megabytes for streaming buffers (default: 16MB).
- `-v`: Enable verbose debug level logging.
- `-cpuprofile <file>`: Write CPU profiling data to specified file.
- `-memprofile <file>`: Write heap profiling data to specified file.

---

## Directory Structure

- `gf16/`: Low-level Galois Field $GF(2^{16})$ field arithmetic.
- `rs/`: Reed-Solomon erasure coder and linear matrix algebra.
- `par2/`: PAR2 parser, Sliding window checksummer, and the core Sandboxed parallel scanning & repair engine.
- `cmd/gopar/`: Standard CLI application interface.
- `tests/`: E2E integration tests validating correctness against canonical `par2cmdline` test suite archives.

---

## Development and Testing

To run all unit, benchmark, and E2E integration tests in the library:

```bash
# Run all tests
go test -v ./...

# Run Low-level Math field benchmarks
go test -v -bench=. ./gf16/...
```
