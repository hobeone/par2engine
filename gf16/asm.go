//go:build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

// gfniLoMask and gfniHiMask are shared by both GFNI kernels. They are declared
// once in main rather than inside the generator, which runs per kernel and
// would otherwise emit each symbol twice.
var gfniLoMask, gfniHiMask Mem

func main() {
	ConstraintExpr("amd64")

	generateMul()
	generateMulAndAdd()
	gfniLoMask = GLOBL("gfni_lo_mask", RODATA|NOPTR)
	for i := range 4 {
		DATA(8*i, U64(0x00ff00ff00ff00ff))
	}
	gfniHiMask = GLOBL("gfni_hi_mask", RODATA|NOPTR)
	for i := range 4 {
		DATA(8*i, U64(0xff00ff00ff00ff00))
	}

	generateGFNIKernel("MulByteSliceLE_GFNI", false)
	generateGFNIKernel("MulAndAddByteSliceLE_GFNI", true)

	Generate()
}

func generateMul() {
	TEXT("MulByteSliceLE_AVX2", 0, "func(tables *[128]byte, in []byte, out []byte)")
	Doc(
		"MulByteSliceLE_AVX2 multiplies each 16-bit element in 'in' by a constant",
		"using AVX2 planar repack and 4-bit shuffles, storing the result in 'out'.",
		"Processes 64 bytes (32 elements) per iteration. len(in) must be a multiple of 64.",
	)

	// 1. Load parameters
	tablesPtr := Mem{Base: Load(Param("tables"), GP64())}
	inPtr := Mem{Base: Load(Param("in").Base(), GP64())}
	inLen := Load(Param("in").Len(), GP64())
	outPtr := Mem{Base: Load(Param("out").Base(), GP64())}

	// 2. Allocate and load 8 YMM registers for the shuffle tables using VPBROADCASTI128
	s0Low := YMM()
	s4Low := YMM()
	s8Low := YMM()
	s12Low := YMM()
	s0High := YMM()
	s4High := YMM()
	s8High := YMM()
	s12High := YMM()

	VBROADCASTI128(tablesPtr.Offset(0), s0Low)
	VBROADCASTI128(tablesPtr.Offset(16), s4Low)
	VBROADCASTI128(tablesPtr.Offset(32), s8Low)
	VBROADCASTI128(tablesPtr.Offset(48), s12Low)
	VBROADCASTI128(tablesPtr.Offset(64), s0High)
	VBROADCASTI128(tablesPtr.Offset(80), s4High)
	VBROADCASTI128(tablesPtr.Offset(96), s8High)
	VBROADCASTI128(tablesPtr.Offset(112), s12High)

	// 3. Allocate masks
	mulMask := YMM()
	convMask := YMM()

	// Set masks
	// mulMask = 0x0F0F...
	mulMaskMem := GLOBL("mul_mask_avx2", RODATA|NOPTR)
	for i := range 4 {
		DATA(8*i, U64(0x0f0f0f0f0f0f0f0f))
	}
	VMOVUPD(mulMaskMem, mulMask)

	// convMask = 0x00FF...
	convMaskMem := GLOBL("conv_mask_avx2", RODATA|NOPTR)
	for i := range 4 {
		DATA(8*i, U64(0x00ff00ff00ff00ff))
	}
	VMOVUPD(convMaskMem, convMask)

	// 4. Loop setup
	AX := GP64()
	MOVQ(inLen, AX)
	SHRQ(Imm(6), AX) // AX = len(in) / 64

	Label("loop")
	CMPQ(AX, Imm(0))
	JE(LabelRef("done"))

	in0 := YMM()
	in1 := YMM()
	VMOVUPD(inPtr.Offset(0), in1)
	VMOVUPD(inPtr.Offset(32), in0)

	// Temporary scratch registers (we have exactly 4 left: Y12, Y13, Y14, Y15)
	tmp0 := YMM()
	tmp1 := YMM()
	tmp2 := YMM()
	tmp3 := YMM()

	// Run planar math
	standardToAltMap(in0, in1, convMask, tmp0, tmp1)
	mulAltMap(s0Low, s4Low, s8Low, s12Low, s0High, s4High, s8High, s12High, tmp0, in0, mulMask, in1, tmp1, tmp2, tmp3)
	altToStandardMap(in1, tmp1, in0)

	// Store (swapped order!)
	VMOVUPD(in0, outPtr.Offset(0))
	VMOVUPD(in1, outPtr.Offset(32))

	ADDQ(Imm(64), inPtr.Base)
	ADDQ(Imm(64), outPtr.Base)
	DECQ(AX)
	JMP(LabelRef("loop"))

	Label("done")
	VZEROUPPER()
	RET()
}

func generateMulAndAdd() {
	TEXT("MulAndAddByteSliceLE_AVX2", 0, "func(tables *[128]byte, in []byte, out []byte)")
	Doc(
		"MulAndAddByteSliceLE_AVX2 multiplies each 16-bit element in 'in' by a constant",
		"using AVX2 planar repack and 4-bit shuffles, XORing the result into 'out'.",
		"Processes 64 bytes (32 elements) per iteration. len(in) must be a multiple of 64.",
	)

	// 1. Load parameters
	tablesPtr := Mem{Base: Load(Param("tables"), GP64())}
	inPtr := Mem{Base: Load(Param("in").Base(), GP64())}
	inLen := Load(Param("in").Len(), GP64())
	outPtr := Mem{Base: Load(Param("out").Base(), GP64())}

	// 2. Load tables
	s0Low := YMM()
	s4Low := YMM()
	s8Low := YMM()
	s12Low := YMM()
	s0High := YMM()
	s4High := YMM()
	s8High := YMM()
	s12High := YMM()

	VBROADCASTI128(tablesPtr.Offset(0), s0Low)
	VBROADCASTI128(tablesPtr.Offset(16), s4Low)
	VBROADCASTI128(tablesPtr.Offset(32), s8Low)
	VBROADCASTI128(tablesPtr.Offset(48), s12Low)
	VBROADCASTI128(tablesPtr.Offset(64), s0High)
	VBROADCASTI128(tablesPtr.Offset(80), s4High)
	VBROADCASTI128(tablesPtr.Offset(96), s8High)
	VBROADCASTI128(tablesPtr.Offset(112), s12High)

	// 3. Load masks
	mulMask := YMM()
	convMask := YMM()

	mulMaskMem := GLOBL("mul_mask_avx2_add", RODATA|NOPTR)
	for i := range 4 {
		DATA(8*i, U64(0x0f0f0f0f0f0f0f0f))
	}
	VMOVUPD(mulMaskMem, mulMask)

	convMaskMem := GLOBL("conv_mask_avx2_add", RODATA|NOPTR)
	for i := range 4 {
		DATA(8*i, U64(0x00ff00ff00ff00ff))
	}
	VMOVUPD(convMaskMem, convMask)

	// 4. Loop setup
	AX := GP64()
	MOVQ(inLen, AX)
	SHRQ(Imm(6), AX)

	Label("loop")
	CMPQ(AX, Imm(0))
	JE(LabelRef("done"))

	in0 := YMM()
	in1 := YMM()
	VMOVUPD(inPtr.Offset(0), in1)
	VMOVUPD(inPtr.Offset(32), in0)

	tmp0 := YMM()
	tmp1 := YMM()
	tmp2 := YMM()
	tmp3 := YMM()

	// Run planar math
	standardToAltMap(in0, in1, convMask, tmp0, tmp1)
	mulAltMap(s0Low, s4Low, s8Low, s12Low, s0High, s4High, s8High, s12High, tmp0, in0, mulMask, in1, tmp1, tmp2, tmp3)
	altToStandardMap(in1, tmp1, in0)

	// Load existing out and XOR
	out0 := YMM()
	out1 := YMM()
	VMOVUPD(outPtr.Offset(0), out0)
	VMOVUPD(outPtr.Offset(32), out1)
	VPXOR(out0, in0, in0)
	VPXOR(out1, in1, in1)

	// Store (swapped!)
	VMOVUPD(in0, outPtr.Offset(0))
	VMOVUPD(in1, outPtr.Offset(32))

	ADDQ(Imm(64), inPtr.Base)
	ADDQ(Imm(64), outPtr.Base)
	DECQ(AX)
	JMP(LabelRef("loop"))

	Label("done")
	VZEROUPPER()
	RET()
}

// Helper functions for planar repack math (AVX2 translation)

func standardToAltMap(in0, in1, convMask, outLow, tmp Register) {
	VMOVDQA(in0, outLow)
	VPSRLW(Imm(8), in0, in0)
	VPAND(convMask, outLow, outLow)

	VMOVDQA(in1, tmp)
	VPSRLW(Imm(8), in1, in1)
	VPAND(convMask, tmp, tmp)

	VPACKUSWB(in1, in0, in0)
	VPACKUSWB(tmp, outLow, outLow)
}

func altToStandardMap(inLow, inHigh, out1 Register) {
	VMOVDQA(inLow, out1)
	VPUNPCKHBW(inHigh, out1, out1)
	VPUNPCKLBW(inHigh, inLow, inLow)
}

func mulAltMapByte(s0, s4, s8, s12, inLow, inHigh, mulMask, out, tmp0, tmp1 Register) {
	VMOVDQA(inLow, tmp0)
	VPAND(mulMask, tmp0, tmp0)
	VMOVDQA(s0, out)
	VPSHUFB(tmp0, out, out)

	VMOVDQA(inLow, tmp0)
	VPSRLW(Imm(4), tmp0, tmp0)
	VPAND(mulMask, tmp0, tmp0)
	VMOVDQA(s4, tmp1)
	VPSHUFB(tmp0, tmp1, tmp1)
	VPXOR(tmp1, out, out)

	VMOVDQA(inHigh, tmp0)
	VPAND(mulMask, tmp0, tmp0)
	VMOVDQA(s8, tmp1)
	VPSHUFB(tmp0, tmp1, tmp1)
	VPXOR(tmp1, out, out)

	VMOVDQA(inHigh, tmp0)
	VPSRLW(Imm(4), tmp0, tmp0)
	VPAND(mulMask, tmp0, tmp0)
	VMOVDQA(s12, tmp1)
	VPSHUFB(tmp0, tmp1, tmp1)
	VPXOR(tmp1, out, out)
}

func mulAltMap(s0Low, s4Low, s8Low, s12Low, s0High, s4High, s8High, s12High, inLow, inHigh, mulMask, outLow, outHigh, tmp0, tmp1 Register) {
	mulAltMapByte(s0Low, s4Low, s8Low, s12Low, inLow, inHigh, mulMask, outLow, tmp0, tmp1)
	mulAltMapByte(s0High, s4High, s8High, s12High, inLow, inHigh, mulMask, outHigh, tmp0, tmp1)
}

// generateGFNIKernel emits a GF(2^16) multiply kernel built on VGF2P8AFFINEQB.
//
// Multiplication by a constant is a GF(2)-linear map on 16 bits, so its 16x16
// matrix splits into four 8x8 blocks, each one affine transform:
//
//	[yl]   [a00 a01] [xl]
//	[yh] = [a10 a11] [xh]
//
// Each transform applies its block to every byte, so the wanted half of each
// result lands in alternating byte positions. Rather than deinterleave into
// planar halves the way the PSHUFB kernel does, the two cross terms are slid
// into place with 16-bit lane shifts and the unwanted halves masked off. The
// data stays interleaved end to end, which removes the pack/unpack round trip
// that dominates the AVX2 path.
//
// The instruction reads row i of its matrix from byte 7-i of the qword; the Go
// side builds the qwords in that order. Processes 32 bytes per iteration.
// If accumulate is true the result is XORed into out rather than stored.
func generateGFNIKernel(name string, accumulate bool) {
	verb := "storing the result in"
	if accumulate {
		verb = "XORing the result into"
	}
	TEXT(name, NOSPLIT, "func(matrices *[4]uint64, in []byte, out []byte)")
	Doc(
		name+" multiplies each 16-bit element in 'in' by the constant whose",
		"GF(2) block matrices are given in 'matrices', "+verb+" 'out'.",
		"Requires GFNI and AVX2. Processes 32 bytes (16 elements) per iteration.",
		"len(in) must be a multiple of 32.",
	)
	// Callers pass a stack-local [4]uint64. Without this the compiler must
	// assume the pointer escapes and moves the matrices to the heap, which
	// would break the package's zero-allocation guarantee.
	Pragma("noescape")

	matPtr := Mem{Base: Load(Param("matrices"), GP64())}
	inPtr := Mem{Base: Load(Param("in").Base(), GP64())}
	inLen := Load(Param("in").Len(), GP64())
	outPtr := Mem{Base: Load(Param("out").Base(), GP64())}

	// One 8x8 block matrix per YMM register, broadcast to every qword lane so
	// the same block applies across the whole vector.
	a00, a01, a10, a11 := YMM(), YMM(), YMM(), YMM()
	VPBROADCASTQ(matPtr.Offset(0), a00)
	VPBROADCASTQ(matPtr.Offset(8), a01)
	VPBROADCASTQ(matPtr.Offset(16), a10)
	VPBROADCASTQ(matPtr.Offset(24), a11)

	loMask, hiMask := YMM(), YMM()
	VMOVDQU(gfniLoMask, loMask)
	VMOVDQU(gfniHiMask, hiMask)

	count := GP64()
	MOVQ(inLen, count)
	SHRQ(Imm(5), count) // 32 bytes per iteration

	Label(name + "_loop")
	CMPQ(count, Imm(0))
	JE(LabelRef(name + "_done"))

	x := YMM()
	VMOVDQU(inPtr.Offset(0), x)

	t00, t01, t10, t11 := YMM(), YMM(), YMM(), YMM()
	VGF2P8AFFINEQB(Imm(0), a00, x, t00)
	VGF2P8AFFINEQB(Imm(0), a01, x, t01)
	VGF2P8AFFINEQB(Imm(0), a10, x, t10)
	VGF2P8AFFINEQB(Imm(0), a11, x, t11)

	// Slide the cross terms into their destination byte and drop the halves
	// each transform computed for the wrong position.
	VPSRLW(Imm(8), t01, t01)
	VPSLLW(Imm(8), t10, t10)
	VPXOR(t00, t01, t01)
	VPXOR(t11, t10, t10)
	VPAND(loMask, t01, t01)
	VPAND(hiMask, t10, t10)

	res := YMM()
	VPOR(t01, t10, res)
	if accumulate {
		prev := YMM()
		VMOVDQU(outPtr.Offset(0), prev)
		VPXOR(prev, res, res)
	}
	VMOVDQU(res, outPtr.Offset(0))

	ADDQ(Imm(32), inPtr.Base)
	ADDQ(Imm(32), outPtr.Base)
	DECQ(count)
	JMP(LabelRef(name + "_loop"))

	Label(name + "_done")
	VZEROUPPER()
	RET()
}
