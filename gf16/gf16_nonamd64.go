//go:build !amd64

package gf16

// blockBytes is one element on a build with no vector kernels: the scalar path
// takes whatever length it is given, so there is no block to align to and
// nothing for a caller to round up to beyond keeping a length even.
var blockBytes = elementBytes

// mulBulkByteSliceLE and mulAndAddBulkByteSliceLE are the non-amd64 halves of
// the two exported functions; see the contract on the declaration beside them in
// gf16.go for what they may assume. With no vector kernels to dispatch to, the
// whole slice is the scalar path's.

func mulBulkByteSliceLE(c T, in, out []byte) {
	mulScalarByteSliceLE(c, in, out)
}

func mulAndAddBulkByteSliceLE(c T, in, out []byte) {
	mulAndAddScalarByteSliceLE(c, in, out)
}
