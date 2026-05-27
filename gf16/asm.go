//go:build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

func main() {
	ConstraintExpr("amd64")

	generateMul()
	generateMulAndAdd()

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
