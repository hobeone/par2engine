//go:build ignore
// +build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
)

func main() {
	ConstraintExpr("amd64")
	
	TEXT("MulByteSliceLE_AVX2", 0, "func(tables *[4][32]byte, in []byte, out []byte)")
	Doc(
		"MulByteSliceLE_AVX2 multiplies each 16-bit element in the 'in' slice by a constant",
		"using AVX2 vector shuffles and the precomputed 4-bit tables, storing the result in 'out'.",
	)

	// 1. Load parameters
	tablesPtr := Mem{Base: Load(Param("tables"), GP64())}
	inPtr := Mem{Base: Load(Param("in").Base(), GP64())}
	inLen := Load(Param("in").Len(), GP64())
	outPtr := Mem{Base: Load(Param("out").Base(), GP64())}

	// 2. Initialize registers and load shuffle tables into YMM registers
	t0 := YMM()
	t1 := YMM()
	t2 := YMM()
	t3 := YMM()
	VMOVUPD(tablesPtr.Offset(0), t0)
	VMOVUPD(tablesPtr.Offset(32), t1)
	VMOVUPD(tablesPtr.Offset(64), t2)
	VMOVUPD(tablesPtr.Offset(96), t3)

	// Masks for nibble splitting
	nibbleMask := YMM()
	VPXOR(nibbleMask, nibbleMask, nibbleMask) // clear
	
	// Setup 0x0F mask in a YMM register
	// We load it from a global constant section
	maskMem := GLOBL("nibble_mask", RODATA|NOPTR)
	for i := range 4 {
		DATA(8*i, U64(0x0f0f0f0f0f0f0f0f))
	}
	VMOVUPD(maskMem, nibbleMask)

	// 3. Setup Loop over input slice
	// Process 32 bytes (16 elements) per iteration
	Label("loop")
	CMPQ(inLen, Imm(32))
	JL(LabelRef("tail"))

	// Load 32 bytes of input data
	data := YMM()
	VMOVUPD(inPtr, data)

	ti := YMM()
	swapped := YMM()
	result := YMM()

	// Step 1: ti = data & 0x0F
	VANDPS(nibbleMask, data, ti)
	// Step 2: swapped = VPSHUFB(shufSwapLoA, ti)
	VPSHUFB(ti, t1, swapped)
	// Step 3: result = VPSHUFB(shufNormLoA, ti)
	VPSHUFB(ti, t0, result)

	// Step 4: ti = (data >> 4) & 0x0F
	VPSRLW(Imm(4), data, ti)
	VANDPS(nibbleMask, ti, ti)
	
	// Step 5: Shuffle high nibbles and XOR
	tempSwapped := YMM()
	tempResult := YMM()
	VPSHUFB(ti, t3, tempSwapped)
	VPSHUFB(ti, t2, tempResult)
	VPXOR(tempSwapped, swapped, swapped)
	VPXOR(tempResult, result, result)

	// Step 6: Fix lane alignment (permute swapped part across 128-bit lanes)
	// swapped = permute2x128(swapped, swapped, 0x01)
	VPERM2I128(Imm(0x01), swapped, swapped, swapped)

	// Step 7: Final XOR
	VPXOR(swapped, result, result)

	// Store 32 bytes to output
	VMOVUPD(result, outPtr)

	// Advance pointers and decrement length
	ADDQ(Imm(32), inPtr.Base)
	ADDQ(Imm(32), outPtr.Base)
	SUBQ(Imm(32), inLen)
	JMP(LabelRef("loop"))

	// 4. Tail / Scalar Fallback
	Label("tail")
	VZEROUPPER()
	RET()

	Generate()
}
