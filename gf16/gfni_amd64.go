//go:build amd64

package gf16

import "github.com/klauspost/cpuid/v2"

// hasGFNI reports whether the GFNI kernels can run. VGF2P8AFFINEQB on YMM
// operands is VEX-encoded by the Go assembler, so it needs AVX2 rather than
// AVX-512 -- which matters, because several client parts ship GFNI with AVX-512
// fused off and still take this path.
var hasGFNI = cpuid.CPU.Supports(cpuid.GFNI, cpuid.AVX2)

// gfniMinBytes is the smallest buffer the GFNI kernel handles: one 32-byte
// iteration. There is no larger threshold because the block matrices are
// tabulated rather than built per call, so entering this path costs nothing
// beyond an index. With the matrices prepared, GFNI beats AVX2 at every size
// measured -- 1.17x at 64 bytes rising to ~1.6x from 128 bytes up.
//
// This matters more than a micro-optimisation. A repair splits each
// memory-limited chunk across goroutines, so the slices reaching this package
// are typically 16 bytes to a few KB, not megabytes. An earlier revision built
// the matrices per call and needed a 16 KB threshold to pay that cost back,
// which no real repair workload ever reached.
const gfniMinBytes = 32

// gfniTable holds the block matrices for all 65536 coefficients: 32 bytes each,
// 2 MB total, a quarter of the SSSE3/AVX2 table in gf16_amd64.go. It is built
// only when the CPU can actually run the kernels, so machines without GFNI pay
// neither the memory nor the roughly 6ms of init.
var gfniTable []gfniBlocks

func init() {
	if !hasGFNI {
		return
	}
	// Relies on logTable/expTable from gf16.go's init, which runs first by
	// alphabetical file order within the package.
	gfniTable = make([]gfniBlocks, 1<<16)
	for i := range gfniTable {
		gfniTable[i] = calcGFNIBlocks(T(i))
	}
}

// gfniBlocks holds the four 8x8 GF(2) blocks of the 16x16 matrix representing
// multiplication by one coefficient, in the row order VGF2P8AFFINEQB expects:
// row i of a block lives in byte 7-i of its qword.
//
// Order is a00, a01, a10, a11 for
//
//	[yl]   [a00 a01] [xl]
//	[yh] = [a10 a11] [xh]
type gfniBlocks [4]uint64

// calcGFNIBlocks builds the block matrices for coefficient c.
//
// Multiplication by c is a GF(2)-linear map on 16 bits, so column j of its
// 16x16 matrix is simply c * x^j. Reading those columns off gives the four
// blocks directly. This is computed per call rather than tabulated: it costs
// about 100ns and saves the 8MB table the SSSE3 and AVX2 paths need.
//
// Must not allocate -- the result is returned by value and passed to the
// kernels as a stack-local pointer.
func calcGFNIBlocks(c T) gfniBlocks {
	var col [16]uint16
	for j := range 16 {
		col[j] = uint16(c.Times(T(1) << uint(j)))
	}

	var rows [4][8]uint8
	for i := range 8 {
		for j := range 8 {
			if col[j]>>i&1 == 1 { // low output bit i from low input bit j
				rows[0][i] |= 1 << j
			}
			if col[j+8]>>i&1 == 1 { // low output bit i from high input bit j
				rows[1][i] |= 1 << j
			}
			if col[j]>>(i+8)&1 == 1 { // high output bit i from low input bit j
				rows[2][i] |= 1 << j
			}
			if col[j+8]>>(i+8)&1 == 1 { // high output bit i from high input bit j
				rows[3][i] |= 1 << j
			}
		}
	}

	var b gfniBlocks
	for k := range 4 {
		var q uint64
		for i := range 8 {
			q |= uint64(rows[k][i]) << (8 * (7 - i))
		}
		b[k] = q
	}
	return b
}
