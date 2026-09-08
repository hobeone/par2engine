//go:build amd64 && !race

package gf16

// Above gfniMinBytes the dispatch switches to the GFNI kernel, which is the only
// path that hands a stack-local pointer -- the block matrices -- to assembly.
// Without //go:noescape on those stubs the matrices are moved to the heap and
// the package's zero-allocation guarantee is lost, so these cases are what
// actually tests that pragma. The arch-independent table tops out well below the
// threshold and would never reach this code.
func init() {
	allocPathCases = append(allocPathCases,
		allocCase{"gfni_whole_blocks", gfniMinBytes},
		allocCase{"gfni_with_tail", gfniMinBytes + 30},
		allocCase{"gfni_large", 256 * 1024},
		allocCase{"gfni_large_with_tail", 256*1024 + 66},
	)
}
