package gf16

import (
	"encoding/binary"
)

// T is an element of GF(2^16).
type T uint16

const order = 1 << 16

var logTable [order - 1]uint16
var expTable [order - 1]T

// MulTable is a 1KB lookup table for a specific coefficient,
// allowing fast multiplication of 16-bit elements 8 bits at a time.
type MulTable struct {
	s0 [256]T
	s8 [256]T
}

func init() {
	// Irreducible polynomial of degree 16 for PAR2: x^16 + x^12 + x^3 + x + 1 -> 0x1100b.
	// Since the 17th bit shifts out of uint16, the 16-bit mask is 0x100b.

	// g is the generator of GF(2^16).
	const g T = 3

	x := T(1)
	for p := range order - 1 {
		if x == 1 && p != 0 {
			panic("repeated power (1)")
		} else if x != 1 && logTable[x-1] != 0 {
			panic("repeated power")
		}
		if expTable[p] != 0 {
			panic("repeated exponent")
		}

		logTable[x-1] = uint16(p)
		expTable[p] = x

		// Double under generator g using slow poly multiplication during bootstrap
		x = x.timesPoly(g)
	}
}

// multByTwo multiplies a 16-bit polynomial by x, reducing it branchlessly.
func multByTwo(p uint16) uint16 {
	return (p << 1) ^ (0x100b & uint16(-int16(p>>15)))
}

// CalcTable populates the 1KB MulTable for coefficient c on the fly.
func CalcTable(c T, table *MulTable) {
	coeff := uint16(c)
	table.s0[0] = 0
	for j := 1; j < 256; j <<= 1 {
		for k := 0; k < j; k++ {
			table.s0[k+j] = table.s0[k] ^ T(coeff)
		}
		coeff = multByTwo(coeff)
	}
	table.s8[0] = 0
	for j := 1; j < 256; j <<= 1 {
		for k := 0; k < j; k++ {
			table.s8[k+j] = table.s8[k] ^ T(coeff)
		}
		coeff = multByTwo(coeff)
	}
}

// MulByteSliceLE treats in and out as arrays of T (stored little-endian),
// and sets each out[i] to c * in[i].
func MulByteSliceLE(c T, in, out []byte) {
	if len(out) != len(in) {
		panic("size mismatch")
	}
	if len(in)%2 != 0 {
		panic("odd slice length")
	}
	if len(in) == 0 {
		return
	}

	var table MulTable
	CalcTable(c, &table)

	n := len(in)
	i := 0

	// Loop unrolled to process 8 bytes (4 elements) at a time
	for ; i <= n-8; i += 8 {
		s0 := in[i]
		s1 := in[i+1]
		s2 := in[i+2]
		s3 := in[i+3]
		s4 := in[i+4]
		s5 := in[i+5]
		s6 := in[i+6]
		s7 := in[i+7]

		r0 := table.s0[s0] ^ table.s8[s1]
		r1 := table.s0[s2] ^ table.s8[s3]
		r2 := table.s0[s4] ^ table.s8[s5]
		r3 := table.s0[s6] ^ table.s8[s7]

		binary.LittleEndian.PutUint16(out[i:], uint16(r0))
		binary.LittleEndian.PutUint16(out[i+2:], uint16(r1))
		binary.LittleEndian.PutUint16(out[i+4:], uint16(r2))
		binary.LittleEndian.PutUint16(out[i+6:], uint16(r3))
	}

	// Handle remaining elements
	for ; i < n; i += 2 {
		cx := table.s0[in[i]] ^ table.s8[in[i+1]]
		binary.LittleEndian.PutUint16(out[i:], uint16(cx))
	}
}

// MulAndAddByteSliceLE treats in and out as arrays of T (stored little-endian),
// and adds (XORs) c * in[i] to out[i].
func MulAndAddByteSliceLE(c T, in, out []byte) {
	if len(out) != len(in) {
		panic("size mismatch")
	}
	if len(in)%2 != 0 {
		panic("odd slice length")
	}
	if len(in) == 0 {
		return
	}

	var table MulTable
	CalcTable(c, &table)

	n := len(in)
	i := 0

	// Loop unrolled to process 8 bytes (4 elements) at a time
	for ; i <= n-8; i += 8 {
		s0 := in[i]
		s1 := in[i+1]
		s2 := in[i+2]
		s3 := in[i+3]
		s4 := in[i+4]
		s5 := in[i+5]
		s6 := in[i+6]
		s7 := in[i+7]

		r0 := table.s0[s0] ^ table.s8[s1]
		r1 := table.s0[s2] ^ table.s8[s3]
		r2 := table.s0[s4] ^ table.s8[s5]
		r3 := table.s0[s6] ^ table.s8[s7]

		d0 := binary.LittleEndian.Uint16(out[i:]) ^ uint16(r0)
		d1 := binary.LittleEndian.Uint16(out[i+2:]) ^ uint16(r1)
		d2 := binary.LittleEndian.Uint16(out[i+4:]) ^ uint16(r2)
		d3 := binary.LittleEndian.Uint16(out[i+6:]) ^ uint16(r3)

		binary.LittleEndian.PutUint16(out[i:], d0)
		binary.LittleEndian.PutUint16(out[i+2:], d1)
		binary.LittleEndian.PutUint16(out[i+4:], d2)
		binary.LittleEndian.PutUint16(out[i+6:], d3)
	}

	// Handle remaining elements
	for ; i < n; i += 2 {
		d := binary.LittleEndian.Uint16(out[i:]) ^ uint16(table.s0[in[i]]^table.s8[in[i+1]])
		binary.LittleEndian.PutUint16(out[i:], d)
	}
}

// Times returns the product of t and u using log/exp tables.
// Slow, but correct fallback for setup and scalar ops.
func (t T) Times(u T) T {
	if t == 0 || u == 0 {
		return 0
	}

	// Slow polynomial multiply if tables are not yet initialized
	if expTable[1] == 0 {
		return t.timesPoly(u)
	}

	logT := int(logTable[t-1])
	logU := int(logTable[u-1])
	return expTable[(logT+logU)%(order-1)]
}

// timesPoly implements slow shift-and-xor polynomial multiplication.
// Used strictly during package init when log/exp tables are empty.
func (t T) timesPoly(u T) T {
	var product T
	a := uint32(t)
	b := uint32(u)
	for b > 0 {
		if b&1 != 0 {
			product ^= T(a)
		}
		a <<= 1
		if a&order != 0 {
			a ^= 0x1100b // full PAR2 polynomial
		}
		b >>= 1
	}
	return product
}

// Inverse returns the multiplicative inverse of t (panics if t == 0).
func (t T) Inverse() T {
	if t == 0 {
		panic("zero has no inverse")
	}
	logT := int(logTable[t-1])
	return expTable[(-logT+(order-1))%(order-1)]
}

// Div returns the product of t and u^{-1} (panics if u == 0).
func (t T) Div(u T) T {
	if u == 0 {
		panic("division by zero")
	}
	if t == 0 {
		return 0
	}
	logT := int(logTable[t-1])
	logU := int(logTable[u-1])
	return expTable[(logT-logU+(order-1))%(order-1)]
}

// Pow returns t^p.
func (t T) Pow(p uint32) T {
	if t == 0 {
		if p == 0 {
			return 1
		}
		return 0
	}
	logT := uint64(logTable[t-1])
	return expTable[(logT*uint64(p))%(order-1)]
}
