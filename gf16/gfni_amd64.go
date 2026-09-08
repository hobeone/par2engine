//go:build amd64

package gf16

import "github.com/klauspost/cpuid/v2"

// hasGFNI reports whether the GFNI kernels can run. VGF2P8AFFINEQB on YMM
// operands is VEX-encoded by the Go assembler, so it needs AVX2 rather than
// AVX-512 -- which matters, because several client parts ship GFNI with AVX-512
// fused off and still take this path.
var hasGFNI = cpuid.CPU.Supports(cpuid.GFNI, cpuid.AVX2)

// gfniMinBytes is the buffer size below which the GFNI path is not worth
// entering. Building the block matrices costs roughly 100ns per call, against
// an AVX2 kernel that needs no setup at all because its tables are precomputed
// for every coefficient at init. Below this size that setup dominates.
//
// Measured by BenchmarkMulDispatchCrossover (ns/op, lower is better):
//
//	bytes    AVX2    GFNI
//	  512    15.4   107.0
//	 4096   118.2   171.1
//	 8192   242.0   254.2   <- AVX2 still marginally ahead
//	16384   478.7   407.4   <- GFNI ahead by ~15%
//	32768   956.8   711.8
//
// The lines cross around 10-11 KB; 16 KB sits safely past it rather than at the
// margin, where the ordering is sensitive to coefficient and cache state.
const gfniMinBytes = 16384

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
