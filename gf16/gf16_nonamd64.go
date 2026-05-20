//go:build !amd64

package gf16

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
