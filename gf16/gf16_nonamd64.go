//go:build !amd64

package gf16

// blockBytes is one element on a build with no vector kernels: the scalar path
// takes whatever length it is given, so there is no block to align to and
// nothing for a caller to round up to beyond keeping a length even.
var blockBytes = elementBytes

// MulByteSliceLE treats in and out as arrays of T (stored little-endian),
// and sets each out[i] to c * in[i].
func MulByteSliceLE(c T, in, out []byte) {
	validateSlicePair(in, out)
	if len(in) == 0 {
		return
	}
	mulScalarByteSliceLE(c, in, out)
}

// MulAndAddByteSliceLE treats in and out as arrays of T (stored little-endian),
// and adds (XORs) c * in[i] to out[i].
func MulAndAddByteSliceLE(c T, in, out []byte) {
	validateSlicePair(in, out)
	if len(in) == 0 {
		return
	}
	mulAndAddScalarByteSliceLE(c, in, out)
}
