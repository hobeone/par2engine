//go:build !race

// This file is excluded under -race deliberately. The race detector allocates
// shadow state for the memory accesses it instruments, so allocation counts
// measured under -race describe the instrumented build rather than the one these
// assertions are about. CI runs the package twice: once with -race for the
// concurrency checks, once without so these assertions execute.

package gf16

import "testing"

// allocRuns is the sample count handed to testing.AllocsPerRun. The measured
// functions are deterministic, so a small number of runs is sufficient; the
// helper additionally performs one warm-up call before it starts counting.
const allocRuns = 50

// allocCoefficient is an arbitrary non-trivial GF(2^16) element. Neither 0 nor 1
// is special-cased in calcTable, but using a value with bits set in every nibble
// keeps the table population representative.
const allocCoefficient = T(0xACE1)

// allocCase is one buffer size to assert against. Declared as a named type so
// gf16_alloc_amd64_test.go can extend the table with amd64-only dispatch paths.
type allocCase struct {
	name string
	size int
}

// allocPathCases enumerates buffer sizes that, between them, reach every dispatch
// branch in MulByteSliceLE and MulAndAddByteSliceLE.
//
// This spread is the substance of the test rather than incidental thoroughness.
// On amd64 with AVX2, MulByteSliceLE forwards any length that is a whole multiple
// of 64 straight to the assembly kernel and never enters mulScalarByteSliceLE --
// which is the only place the 1 KB mulTable is declared as a local. A test that
// measured a single large aligned buffer would therefore report zero allocations
// while never once exercising the stack-allocation guarantee it claims to defend.
// Sizes must be even; validateSlicePair panics on odd lengths.
//
// The one shape not reachable from here is the hasAVX2/hasSSSE3 false branch:
// those are package-level vars set from CPU detection at init, so exercising the
// pure-scalar dispatch on an AVX2 machine would require making them injectable.
var allocPathCases = []allocCase{
	{"empty", 0},                    // n == 0 early return, before any dispatch
	{"scalar_only", 8},              // below every vector threshold
	{"ssse3_block", 32},             // one SSSE3 block, below the AVX2 threshold
	{"ssse3_with_tail", 38},         // one SSSE3 block plus a 6-byte scalar tail
	{"avx2_block", 64},              // one whole AVX2 block, no scalar tail
	{"avx2_with_scalar_tail", 70},   // one AVX2 block plus a 6-byte scalar tail
	{"avx2_then_ssse3_tail", 100},   // AVX2 block, then SSSE3 block, then scalar tail
	{"multi_block", 4096},           // many whole AVX2 blocks
	{"multi_block_with_tail", 4102}, // many AVX2 blocks plus a scalar tail
}

// TestMulByteSliceLEZeroAlloc asserts the zero-heap-allocation guarantee that the
// rest of the engine depends on: MulByteSliceLE is called once per shard per
// chunk during repair, so a single heap allocation here multiplies across the
// whole recovery.
//
// Subtests must not call t.Parallel. testing.AllocsPerRun reads process-wide
// memory statistics and pins GOMAXPROCS for the duration of its sample, so
// concurrent subtests would contaminate each other's measurements.
func TestMulByteSliceLEZeroAlloc(t *testing.T) {
	for _, tc := range allocPathCases {
		t.Run(tc.name, func(t *testing.T) {
			in := make([]byte, tc.size)
			out := make([]byte, tc.size)
			for i := range in {
				in[i] = byte(i)
			}

			avg := testing.AllocsPerRun(allocRuns, func() {
				MulByteSliceLE(allocCoefficient, in, out)
			})

			if avg != 0 {
				t.Errorf("MulByteSliceLE(size=%d) allocated %v times per call, want 0; "+
					"the 1 KB mulTable has likely escaped to the heap", tc.size, avg)
			}
		})
	}
}

// TestMulAndAddByteSliceLEZeroAlloc is the counterpart assertion for the
// multiply-accumulate kernel, which carries the same guarantee and is the hotter
// of the two during Reed-Solomon reconstruction.
func TestMulAndAddByteSliceLEZeroAlloc(t *testing.T) {
	for _, tc := range allocPathCases {
		t.Run(tc.name, func(t *testing.T) {
			in := make([]byte, tc.size)
			out := make([]byte, tc.size)
			for i := range in {
				in[i] = byte(i)
			}

			avg := testing.AllocsPerRun(allocRuns, func() {
				MulAndAddByteSliceLE(allocCoefficient, in, out)
			})

			if avg != 0 {
				t.Errorf("MulAndAddByteSliceLE(size=%d) allocated %v times per call, want 0; "+
					"the 1 KB mulTable has likely escaped to the heap", tc.size, avg)
			}
		})
	}
}
