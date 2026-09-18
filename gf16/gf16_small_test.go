package gf16

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// The scalar kernels take one of two shapes depending on length: at or below
// smallSliceBytes they multiply element by element, above it they build the 1 KB
// mulTable first. These tests pin that the choice is invisible in the output --
// the threshold is a performance decision and must never be an arithmetic one.

// refMulLE is the TABLE path, run without its length threshold: build the 1 KB
// mulTable and read every element out of it.
//
// It must not be a copy of the small path's own loop. An earlier version of this
// file multiplied through T.Times, which is exactly what the small path does, so
// for every length at or below the threshold -- the only lengths this test is
// about -- it compared that loop against itself and would have passed whatever
// the table did. The claim under test is that the two SHAPES agree, so the
// reference has to be the shape the kernels no longer take.
func refMulLE(c T, in []byte) []byte {
	var table mulTable
	calcTable(c, &table)

	out := make([]byte, len(in))
	for i := 0; i+1 < len(in); i += 2 {
		binary.LittleEndian.PutUint16(out[i:], uint16(table.s0[in[i]]^table.s8[in[i+1]]))
	}
	return out
}

// smallTestSizes straddles smallSliceBytes so both kernel shapes run. 64 and 66
// are the boundary itself: the threshold is inclusive, so 64 takes the small
// path and 66 is the shortest input that builds a table.
var smallTestSizes = []int{0, 2, 4, 16, 26, 30, 62, 64, 66, 128, 256, 1024}

// smallTestCoefficients covers the values calcTable and Times treat specially
// (0 and 1) plus arbitrary ones with bits across both halves.
var smallTestCoefficients = []T{0, 1, 2, 0x00FF, 0xACE1, 0xFFFF}

func patternedBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 1)
	}
	return b
}

func TestScalarKernelsAgreeAcrossTheSmallSliceThreshold(t *testing.T) {
	for _, size := range smallTestSizes {
		for _, c := range smallTestCoefficients {
			t.Run(fmt.Sprintf("mul/size=%d/c=%#04x", size, c), func(t *testing.T) {
				in := patternedBytes(size)
				got := make([]byte, size)
				mulScalarByteSliceLE(c, in, got)

				if want := refMulLE(c, in); !bytes.Equal(got, want) {
					t.Errorf("mulScalarByteSliceLE(size=%d, c=%#04x) = %x, want %x", size, c, got, want)
				}
			})

			t.Run(fmt.Sprintf("muladd/size=%d/c=%#04x", size, c), func(t *testing.T) {
				in := patternedBytes(size)
				acc := patternedBytes(size)
				for i := range acc {
					acc[i] ^= 0x5A
				}

				want := make([]byte, size)
				copy(want, acc)
				product := refMulLE(c, in)
				for i := range want {
					want[i] ^= product[i]
				}

				mulAndAddScalarByteSliceLE(c, in, acc)
				if !bytes.Equal(acc, want) {
					t.Errorf("mulAndAddScalarByteSliceLE(size=%d, c=%#04x) = %x, want %x", size, c, acc, want)
				}
			})
		}
	}
}

// TestExportedKernelsAgreeWithReference runs the same comparison through the
// exported entry points, so the vector dispatch and the scalar tail it leaves
// are covered together. A tail is never longer than 30 bytes on amd64, so the
// sizes that are not whole blocks are what exercise the small path in
// production.
func TestExportedKernelsAgreeWithReference(t *testing.T) {
	for _, size := range []int{2, 16, 30, 64, 70, 100, 240, 368, 4102} {
		for _, c := range smallTestCoefficients {
			in := patternedBytes(size)
			want := refMulLE(c, in)

			got := make([]byte, size)
			MulByteSliceLE(c, in, got)
			if !bytes.Equal(got, want) {
				t.Errorf("MulByteSliceLE(size=%d, c=%#04x) = %x, want %x", size, c, got, want)
			}

			// The accumulating kernel is the hotter of the two in a repair, so
			// it gets the same coverage rather than being assumed to follow.
			acc := make([]byte, size)
			copy(acc, patternedBytes(size))
			accWant := make([]byte, size)
			copy(accWant, acc)
			for i := range accWant {
				accWant[i] ^= want[i]
			}

			MulAndAddByteSliceLE(c, in, acc)
			if !bytes.Equal(acc, accWant) {
				t.Errorf("MulAndAddByteSliceLE(size=%d, c=%#04x) = %x, want %x", size, c, acc, accWant)
			}
		}
	}
}

func runMulScalarSmallBenchmark(b *testing.B, size int) {
	in := patternedBytes(size)
	out := make([]byte, size)
	b.SetBytes(int64(size))
	for b.Loop() {
		mulScalarByteSliceLE(T(0x1234), in, out)
	}
}

// The scalar kernels are reached with a tail, never with bulk data: an AVX2
// dispatch leaves at most 30 bytes and Gaussian elimination calls in with 26.
// These sizes are the ones a repair actually pays for, so a regression at this
// end is visible rather than inferred from the 1 KB and larger benchmarks.
func BenchmarkMulByteSliceLEScalar_16B(b *testing.B) { runMulScalarSmallBenchmark(b, 16) }
func BenchmarkMulByteSliceLEScalar_26B(b *testing.B) { runMulScalarSmallBenchmark(b, 26) }
func BenchmarkMulByteSliceLEScalar_64B(b *testing.B) { runMulScalarSmallBenchmark(b, 64) }
func BenchmarkMulByteSliceLEScalar_66B(b *testing.B) { runMulScalarSmallBenchmark(b, 66) }
