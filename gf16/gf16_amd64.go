//go:build amd64

package gf16

import (
	"unsafe"

	"github.com/klauspost/cpuid/v2"
)

// mulTable64Entry holds the SSSE3 lookup tables for a single GF(2^16) coefficient.
// Each GF(2^16) multiply is decomposed into four 4-bit nibble lookups (s0, s4, s8, s12),
// one per nibble of the 16-bit input element. Each table has 16 entries (one per nibble
// value) and fits exactly in one XMM register, enabling PSHUFB to do 16 parallel lookups
// per instruction.
//
// Layout (128 bytes total, 16 bytes per field):
//
//	[  0: 16] s0Low   — low  bytes of c * j          for j = 0..15
//	[ 16: 32] s4Low   — low  bytes of c * (j << 4)   for j = 0..15
//	[ 32: 48] s8Low   — low  bytes of c * (j << 8)   for j = 0..15
//	[ 48: 64] s12Low  — low  bytes of c * (j << 12)  for j = 0..15
//	[ 64: 80] s0High  — high bytes of c * j          for j = 0..15
//	[ 80: 96] s4High  — high bytes of c * (j << 4)   for j = 0..15
//	[ 96:112] s8High  — high bytes of c * (j << 8)   for j = 0..15
//	[112:128] s12High — high bytes of c * (j << 12)  for j = 0..15
type mulTable64Entry struct {
	s0Low, s4Low, s8Low, s12Low     [16]byte
	s0High, s4High, s8High, s12High [16]byte
}

// mulTable64 is the precomputed SSSE3 table for all 65536 possible coefficients (8 MB).
var mulTable64 [1 << 16]mulTable64Entry

// hasSSSE3 is true when the CPU supports SSSE3 (required for PSHUFB).
var hasSSSE3 = cpuid.CPU.Supports(cpuid.SSSE3)

// hasAVX2 is true when the CPU supports AVX2 (required for VBROADCASTI128/planar repack).
var hasAVX2 = cpuid.CPU.Supports(cpuid.AVX2)

// Block sizes the vector kernels consume per iteration. The dispatch below
// peels whole blocks and leaves the remainder to the scalar path, so these are
// also what decides how long a scalar tail can be.
const (
	avx2BlockBytes  = 64
	ssse3BlockBytes = 32
)

// blockBytes reports the largest run of bytes a single kernel call consumes on
// this CPU, which is what a caller slicing work up should align to. See
// KernelBlockBytes.
var blockBytes = func() int {
	switch {
	case hasAVX2:
		return avx2BlockBytes
	case hasSSSE3:
		return ssse3BlockBytes
	default:
		return elementBytes
	}
}()

func init() {
	// Relies on logTable/expTable already populated by gf16.go's init (runs first by
	// alphabetical file order within the package).
	for i := range mulTable64 {
		c := T(i)
		e := &mulTable64[i]
		for j := range 16 {
			t0 := c.Times(T(j))
			e.s0Low[j] = byte(t0)
			e.s0High[j] = byte(t0 >> 8)

			t1 := c.Times(T(j << 4))
			e.s4Low[j] = byte(t1)
			e.s4High[j] = byte(t1 >> 8)

			t2 := c.Times(T(j << 8))
			e.s8Low[j] = byte(t2)
			e.s8High[j] = byte(t2 >> 8)

			t3 := c.Times(T(j << 12))
			e.s12Low[j] = byte(t3)
			e.s12High[j] = byte(t3 >> 8)
		}
	}
}

// Assembly implementations — the //go:noescape annotation is required to prevent the
// compiler from concluding that the slice arguments escape to the heap.

//go:noescape
func mulSliceSSSE3(cEntry *mulTable64Entry, in, out []byte)

//go:noescape
func mulAndAddSliceSSSE3(cEntry *mulTable64Entry, in, out []byte)

// mulBulkByteSliceLE is the amd64 half of MulByteSliceLE; see the contract on
// the declaration beside it in gf16.go for what it may assume.
//
// With SSSE3 the bulk of the work is done by the vectorized path (32 bytes = 16
// elements per loop iteration via PSHUFB). Any trailing bytes that don't fill a
// complete 32-byte chunk fall through to the scalar path.
func mulBulkByteSliceLE(c T, in, out []byte) {
	n := len(in)

	if hasAVX2 {
		avx2Len := n - (n % avx2BlockBytes)
		if avx2Len > 0 {
			MulByteSliceLE_AVX2((*[128]byte)(unsafe.Pointer(&mulTable64[c])), in[:avx2Len], out[:avx2Len])
			if avx2Len < n {
				// The remainder, not the exported entry point: it is nonempty by
				// the test above and c is unchanged, so re-running the guards
				// would answer questions already answered.
				mulBulkByteSliceLE(c, in[avx2Len:], out[avx2Len:])
			}
			return
		}
	}

	if hasSSSE3 {
		ssse3Len := n - (n % ssse3BlockBytes)
		if ssse3Len > 0 {
			mulSliceSSSE3(&mulTable64[c], in[:ssse3Len], out[:ssse3Len])
		}
		if ssse3Len < n {
			mulScalarByteSliceLE(c, in[ssse3Len:], out[ssse3Len:])
		}
		return
	}

	mulScalarByteSliceLE(c, in, out)
}

// mulAndAddBulkByteSliceLE is the amd64 half of MulAndAddByteSliceLE; see the
// contract on the declaration beside it in gf16.go for what it may assume.
//
// With SSSE3 the bulk of the work is done by the vectorized path. Any trailing
// bytes fall through to the scalar path.
func mulAndAddBulkByteSliceLE(c T, in, out []byte) {
	n := len(in)

	if hasAVX2 {
		avx2Len := n - (n % avx2BlockBytes)
		if avx2Len > 0 {
			MulAndAddByteSliceLE_AVX2((*[128]byte)(unsafe.Pointer(&mulTable64[c])), in[:avx2Len], out[:avx2Len])
			if avx2Len < n {
				// See mulBulkByteSliceLE for why this is the remainder rather
				// than the exported entry point.
				mulAndAddBulkByteSliceLE(c, in[avx2Len:], out[avx2Len:])
			}
			return
		}
	}

	if hasSSSE3 {
		ssse3Len := n - (n % ssse3BlockBytes)
		if ssse3Len > 0 {
			mulAndAddSliceSSSE3(&mulTable64[c], in[:ssse3Len], out[:ssse3Len])
		}
		if ssse3Len < n {
			mulAndAddScalarByteSliceLE(c, in[ssse3Len:], out[ssse3Len:])
		}
		return
	}

	mulAndAddScalarByteSliceLE(c, in, out)
}
