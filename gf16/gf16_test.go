package gf16

import (
	"encoding/binary"
	"math/rand/v2" // Target Go 1.26, modern rand/v2
	"slices"
	"testing"
)

func TestInverse(t *testing.T) {
	for i := 1; i < order; i++ {
		x := T(i)
		xInv := x.Inverse()
		if xInv == 0 {
			t.Fatalf("Inverse(%d) is zero", x)
		}
		prod := x.Times(xInv)
		if prod != 1 {
			t.Fatalf("x * x^-1 = %d, want 1 (x=%d, inv=%d)", prod, x, xInv)
		}
	}
}

func TestTimesDiv(t *testing.T) {
	for i := 1; i < order; i += 123 { // stride to keep test fast but representative
		for j := 1; j < order; j += 456 {
			x := T(i)
			y := T(j)
			p := x.Times(y)
			if p.Div(y) != x {
				t.Fatalf("(%d * %d) / %d != %d", x, y, y, x)
			}
			if p.Div(x) != y {
				t.Fatalf("(%d * %d) / %d != %d", x, y, x, y)
			}
		}
	}
}

func TestPow(t *testing.T) {
	requireEqual := func(tb testing.TB, want, got T) {
		tb.Helper()
		if want != got {
			tb.Fatalf("want %d, got %d", want, got)
		}
	}

	requireEqual(t, T(1), T(0).Pow(0))
	requireEqual(t, T(0), T(0).Pow(1))
	requireEqual(t, T(1), T(5).Pow(0))
	requireEqual(t, T(5), T(5).Pow(1))
	requireEqual(t, T(5).Times(T(5)), T(5).Pow(2))
	requireEqual(t, T(5).Times(T(5)).Times(T(5)), T(5).Pow(3))
}

func TestCalcTable(t *testing.T) {
	for c := range order {
		var table MulTable
		CalcTable(T(c), &table)
		for j := range 256 {
			want0 := T(c).Times(T(j))
			if table.s0[j] != want0 {
				t.Fatalf("c=%d j=%d table.s0: want %d, got %d", c, j, want0, table.s0[j])
			}
			want8 := T(c).Times(T(j << 8))
			if table.s8[j] != want8 {
				t.Fatalf("c=%d j=%d table.s8: want %d, got %d", c, j, want8, table.s8[j])
			}
		}
	}
}

func TestMulByteSliceLE(t *testing.T) {
	r := rand.New(rand.NewPCG(42, 42))
	in := make([]byte, 1024)
	for i := range in {
		in[i] = byte(r.Uint32())
	}
	out := make([]byte, len(in))
	c := T(0x4321)

	MulByteSliceLE(c, in, out)

	// Verify correctness sequentially
	for i := 0; i < len(in); i += 2 {
		inVal := T(binary.LittleEndian.Uint16(in[i:]))
		want := c.Times(inVal)
		got := T(binary.LittleEndian.Uint16(out[i:]))
		if want != got {
			t.Fatalf("index %d: want %d, got %d", i, want, got)
		}
	}
}

func TestMulAndAddByteSliceLE(t *testing.T) {
	r := rand.New(rand.NewPCG(42, 42))
	in := make([]byte, 1024)
	out := make([]byte, 1024)
	for i := range in {
		in[i] = byte(r.Uint32())
		out[i] = byte(r.Uint32())
	}
	outOrig := make([]byte, len(out))
	copy(outOrig, out)

	c := T(0x4321)

	MulAndAddByteSliceLE(c, in, out)

	// Verify correctness sequentially
	for i := 0; i < len(in); i += 2 {
		inVal := T(binary.LittleEndian.Uint16(in[i:]))
		outOrigVal := T(binary.LittleEndian.Uint16(outOrig[i:]))
		want := outOrigVal ^ c.Times(inVal)
		got := T(binary.LittleEndian.Uint16(out[i:]))
		if want != got {
			t.Fatalf("index %d: want %d, got %d", i, want, got)
		}
	}
}

// TestMulByteSliceLE_DispatchBoundaries exercises sizes straddling the 32-byte SSSE3
// chunk boundary: pure-scalar (< 32), exact chunk, chunk + scalar remainder.
func TestMulByteSliceLE_DispatchBoundaries(t *testing.T) {
	r := rand.New(rand.NewPCG(99, 99))
	c := T(0x4321)

	for _, size := range []int{2, 4, 30, 32, 34, 62, 64, 66, 96, 128, 130} {
		in := make([]byte, size)
		for i := range in {
			in[i] = byte(r.Uint32())
		}
		out := make([]byte, size)

		MulByteSliceLE(c, in, out)

		for i := 0; i < size; i += 2 {
			inVal := T(binary.LittleEndian.Uint16(in[i:]))
			want := c.Times(inVal)
			got := T(binary.LittleEndian.Uint16(out[i:]))
			if want != got {
				t.Fatalf("size=%d index %d: want %#x, got %#x", size, i, want, got)
			}
		}
	}
}

// TestMulAndAddByteSliceLE_DispatchBoundaries mirrors the above for MulAndAdd.
func TestMulAndAddByteSliceLE_DispatchBoundaries(t *testing.T) {
	r := rand.New(rand.NewPCG(99, 99))
	c := T(0x4321)

	for _, size := range []int{2, 4, 30, 32, 34, 62, 64, 66, 96, 128, 130} {
		in := make([]byte, size)
		out := make([]byte, size)
		for i := range in {
			in[i] = byte(r.Uint32())
			out[i] = byte(r.Uint32())
		}
		outOrig := slices.Clone(out)

		MulAndAddByteSliceLE(c, in, out)

		for i := 0; i < size; i += 2 {
			inVal := T(binary.LittleEndian.Uint16(in[i:]))
			origVal := T(binary.LittleEndian.Uint16(outOrig[i:]))
			want := origVal ^ c.Times(inVal)
			got := T(binary.LittleEndian.Uint16(out[i:]))
			if want != got {
				t.Fatalf("size=%d index %d: want %#x, got %#x", size, i, want, got)
			}
		}
	}
}

// ---------- CPU Benchmarks ----------

func runMulBenchmark(b *testing.B, size int) {
	in := make([]byte, size)
	out := make([]byte, size)
	c := T(0x1234)

	b.ResetTimer()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		MulByteSliceLE(c, in, out)
	}
}

func BenchmarkMulByteSliceLE_1K(b *testing.B)  { runMulBenchmark(b, 1024) }
func BenchmarkMulByteSliceLE_64K(b *testing.B) { runMulBenchmark(b, 64*1024) }
func BenchmarkMulByteSliceLE_1M(b *testing.B)  { runMulBenchmark(b, 1024*1024) }
func BenchmarkMulByteSliceLE_16M(b *testing.B) { runMulBenchmark(b, 16*1024*1024) }

func runMulAndAddBenchmark(b *testing.B, size int) {
	in := make([]byte, size)
	out := make([]byte, size)
	c := T(0x1234)

	b.ResetTimer()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		MulAndAddByteSliceLE(c, in, out)
	}
}

func BenchmarkMulAndAddByteSliceLE_1K(b *testing.B)  { runMulAndAddBenchmark(b, 1024) }
func BenchmarkMulAndAddByteSliceLE_64K(b *testing.B) { runMulAndAddBenchmark(b, 64*1024) }
func BenchmarkMulAndAddByteSliceLE_1M(b *testing.B)  { runMulAndAddBenchmark(b, 1024*1024) }
func TestMulByteSliceLE_EdgeCases(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03, 0x04}
	out := make([]byte, 4)

	t.Run("zero_coeff", func(t *testing.T) {
		MulByteSliceLE(0, in, out)
		for _, b := range out {
			if b != 0 {
				t.Errorf("expected 0, got %02x", b)
			}
		}
	})

	t.Run("unit_coeff", func(t *testing.T) {
		MulByteSliceLE(1, in, out)
		if !slices.Equal(in, out) {
			t.Errorf("expected %v, got %v", in, out)
		}
	})

	t.Run("empty_slice", func(t *testing.T) {
		MulByteSliceLE(0x1234, nil, nil)           // Should not panic
		MulByteSliceLE(0x1234, []byte{}, []byte{}) // Should not panic
	})
}

func TestMulAndAddByteSliceLE_EdgeCases(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03, 0x04}
	out := []byte{0x10, 0x20, 0x30, 0x40}
	outOrig := slices.Clone(out)

	t.Run("zero_coeff", func(t *testing.T) {
		MulAndAddByteSliceLE(0, in, out)
		if !slices.Equal(out, outOrig) {
			t.Errorf("expected %v, got %v", outOrig, out)
		}
	})

	t.Run("unit_coeff", func(t *testing.T) {
		copy(out, outOrig)
		MulAndAddByteSliceLE(1, in, out)
		for i := range out {
			if out[i] != (outOrig[i] ^ in[i]) {
				t.Errorf("idx %d: expected %02x, got %02x", i, outOrig[i]^in[i], out[i])
			}
		}
	})

	t.Run("empty_slice", func(t *testing.T) {
		MulAndAddByteSliceLE(0x1234, nil, nil)           // Should not panic
		MulAndAddByteSliceLE(0x1234, []byte{}, []byte{}) // Should not panic
	})
}

// ---------- Scalar-path Benchmarks (for side-by-side comparison with SSSE3) ----------
// These call the scalar implementation directly, giving an apples-to-apples comparison
// against the dispatched BenchmarkMulByteSliceLE_* benchmarks above (which use SSSE3
// on amd64).

func runMulScalarBenchmark(b *testing.B, size int) {
	in := make([]byte, size)
	out := make([]byte, size)
	c := T(0x1234)

	b.ResetTimer()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		mulScalarByteSliceLE(c, in, out)
	}
}

func BenchmarkMulByteSliceLEScalar_1K(b *testing.B)  { runMulScalarBenchmark(b, 1024) }
func BenchmarkMulByteSliceLEScalar_64K(b *testing.B) { runMulScalarBenchmark(b, 64*1024) }
func BenchmarkMulByteSliceLEScalar_1M(b *testing.B)  { runMulScalarBenchmark(b, 1024*1024) }
func BenchmarkMulByteSliceLEScalar_16M(b *testing.B) { runMulScalarBenchmark(b, 16*1024*1024) }

func runMulAndAddScalarBenchmark(b *testing.B, size int) {
	in := make([]byte, size)
	out := make([]byte, size)
	c := T(0x1234)

	b.ResetTimer()
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		mulAndAddScalarByteSliceLE(c, in, out)
	}
}

func BenchmarkMulAndAddByteSliceLEScalar_1K(b *testing.B)  { runMulAndAddScalarBenchmark(b, 1024) }
func BenchmarkMulAndAddByteSliceLEScalar_64K(b *testing.B) { runMulAndAddScalarBenchmark(b, 64*1024) }
func BenchmarkMulAndAddByteSliceLEScalar_1M(b *testing.B)  { runMulAndAddScalarBenchmark(b, 1024*1024) }
func BenchmarkMulAndAddByteSliceLEScalar_16M(b *testing.B) {
	runMulAndAddScalarBenchmark(b, 16*1024*1024)
}
