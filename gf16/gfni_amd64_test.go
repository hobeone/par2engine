//go:build amd64

package gf16

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"
	"unsafe"
)

// TestGFNIAvailability makes the dispatch decision visible in test output. The
// GFNI kernels are unreachable on hardware without the feature, and a silent
// skip is indistinguishable from a passing test -- so state plainly which paths
// the rest of this file could actually exercise.
func TestGFNIAvailability(t *testing.T) {
	t.Logf("hasGFNI=%v hasAVX2=%v hasSSSE3=%v (gfniMinBytes=%d)", hasGFNI, hasAVX2, hasSSSE3, gfniMinBytes)
	if !hasGFNI {
		t.Log("GFNI kernels are NOT exercised on this machine; the tests below only cover the AVX2/SSSE3/scalar paths")
	}
}

// gfniTestSizes spans the dispatch threshold and includes remainders, so the
// GFNI block loop, its tail hand-off, and the sub-threshold fallback are all
// covered. Sizes must be even.
var gfniTestSizes = []int{
	gfniMinBytes - 2,  // just below the threshold: must not take the GFNI path
	gfniMinBytes,      // exactly at the threshold, whole 32-byte blocks
	gfniMinBytes + 2,  // threshold plus a 2-byte tail
	gfniMinBytes + 30, // tail just under one block
	gfniMinBytes + 32, // one extra whole block
	gfniMinBytes + 94, // several blocks plus a 30-byte tail
	64 * 1024,         // comfortably above, whole blocks
	64*1024 + 66,      // large with a tail that itself needs sub-dispatch
}

func TestMulByteSliceLEGFNIMatchesScalar(t *testing.T) {
	if !hasGFNI {
		t.Skip("CPU lacks GFNI; kernel cannot be exercised here")
	}
	for _, size := range gfniTestSizes {
		in := make([]byte, size)
		for i := range in {
			in[i] = byte(rand.UintN(256))
		}
		got := make([]byte, size)
		want := make([]byte, size)

		for range 20 {
			c := T(rand.UintN(1 << 16))
			MulByteSliceLE(c, in, got)
			mulScalarByteSliceLE(c, in, want)
			if !bytes.Equal(got, want) {
				t.Fatalf("size=%d c=%#x: dispatched result disagrees with scalar reference", size, c)
			}
		}
	}
}

func TestMulAndAddByteSliceLEGFNIMatchesScalar(t *testing.T) {
	if !hasGFNI {
		t.Skip("CPU lacks GFNI; kernel cannot be exercised here")
	}
	for _, size := range gfniTestSizes {
		in := make([]byte, size)
		seed := make([]byte, size)
		for i := range in {
			in[i] = byte(rand.UintN(256))
			seed[i] = byte(rand.UintN(256))
		}
		got := make([]byte, size)
		want := make([]byte, size)

		for range 20 {
			c := T(rand.UintN(1 << 16))
			copy(got, seed)
			copy(want, seed)
			MulAndAddByteSliceLE(c, in, got)
			mulAndAddScalarByteSliceLE(c, in, want)
			if !bytes.Equal(got, want) {
				t.Fatalf("size=%d c=%#x: dispatched accumulate disagrees with scalar reference", size, c)
			}
		}
	}
}

// TestGFNIKernelDirect exercises the assembly kernels without going through
// MulByteSliceLE, so the kernel is covered independently of gfniMinBytes. A
// later change to that threshold cannot silently stop testing this code.
func TestGFNIKernelDirect(t *testing.T) {
	if !hasGFNI {
		t.Skip("CPU lacks GFNI; kernel cannot be exercised here")
	}
	for _, size := range []int{32, 64, 320, 4096} { // whole 32-byte blocks only
		in := make([]byte, size)
		for i := range in {
			in[i] = byte(rand.UintN(256))
		}
		got := make([]byte, size)
		want := make([]byte, size)

		for range 20 {
			c := T(rand.UintN(1 << 16))
			blocks := calcGFNIBlocks(c)

			MulByteSliceLE_GFNI((*[4]uint64)(&blocks), in, got)
			mulScalarByteSliceLE(c, in, want)
			if !bytes.Equal(got, want) {
				t.Fatalf("MulByteSliceLE_GFNI size=%d c=%#x: disagrees with scalar reference", size, c)
			}

			// Accumulate against a non-zero destination, or an XOR-into bug
			// would be invisible.
			for i := range got {
				got[i] = byte(i)
				want[i] = byte(i)
			}
			MulAndAddByteSliceLE_GFNI((*[4]uint64)(&blocks), in, got)
			mulAndAddScalarByteSliceLE(c, in, want)
			if !bytes.Equal(got, want) {
				t.Fatalf("MulAndAddByteSliceLE_GFNI size=%d c=%#x: disagrees with scalar reference", size, c)
			}
		}
	}
}

// TestCalcGFNIBlocksMatchesFieldMultiply validates the matrix construction
// against the field arithmetic directly, scalar-first. VGF2P8AFFINEQB reads row
// i of its matrix from byte 7-i of the qword; getting that ordering backwards
// produces plausible-looking wrong answers rather than an obvious failure, so
// the encoding is pinned here independently of the assembly.
func TestCalcGFNIBlocksMatchesFieldMultiply(t *testing.T) {
	row := func(q uint64, i int) uint8 { return uint8(q >> (8 * (7 - i))) }
	parity := func(v uint8) uint16 {
		var p uint16
		for b := range 8 {
			p ^= uint16(v>>b) & 1
		}
		return p
	}

	for range 2000 {
		c := T(rand.UintN(1 << 16))
		x := T(rand.UintN(1 << 16))
		b := calcGFNIBlocks(c)

		xl, xh := uint8(x), uint8(x>>8)
		var got uint16
		for i := range 8 {
			lo := parity(row(b[0], i)&xl) ^ parity(row(b[1], i)&xh)
			hi := parity(row(b[2], i)&xl) ^ parity(row(b[3], i)&xh)
			got |= lo << i
			got |= hi << (i + 8)
		}
		if want := uint16(c.Times(x)); got != want {
			t.Fatalf("c=%#x x=%#x: blocks give %#x, field multiply gives %#x", c, x, got, want)
		}
	}
}

// BenchmarkMulDispatchCrossover measures the two kernels head to head across
// the region where gfniMinBytes sits. The GFNI kernel must rebuild its block
// matrices per call (~100ns) while the AVX2 kernel indexes a table precomputed
// at init, so AVX2 wins on small buffers and loses on large ones. The threshold
// should sit just past where the lines cross.
func BenchmarkMulDispatchCrossover(b *testing.B) {
	if !hasGFNI {
		b.Skip("CPU lacks GFNI")
	}
	c := T(0xACE1)
	for _, size := range []int{512, 1024, 2048, 4096, 8192, 16384, 32768} {
		in := make([]byte, size)
		out := make([]byte, size)

		b.Run(fmt.Sprintf("avx2/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				MulByteSliceLE_AVX2((*[128]byte)(unsafe.Pointer(&mulTable64[c])), in, out)
			}
		})
		b.Run(fmt.Sprintf("gfni/%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				blocks := calcGFNIBlocks(c)
				MulByteSliceLE_GFNI((*[4]uint64)(&blocks), in, out)
			}
		})
	}
}
