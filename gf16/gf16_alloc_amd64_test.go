//go:build amd64 && !race

package gf16

// Larger buffers for the GFNI dispatch tier. On hardware with GFNI these sizes
// run the affine kernel rather than AVX2, so without them the tier that handles
// almost all real traffic would never appear in the allocation assertions.
//
// These do not test the //go:noescape pragma on the GFNI stubs: the block
// matrices live in a package-level table, so the kernels receive a global
// pointer and removing the pragma does not by itself cause an allocation here.
func init() {
	allocPathCases = append(allocPathCases,
		allocCase{"gfni_whole_blocks", gfniMinBytes},
		allocCase{"gfni_with_tail", gfniMinBytes + 30},
		allocCase{"gfni_large", 256 * 1024},
		allocCase{"gfni_large_with_tail", 256*1024 + 66},
	)
}
