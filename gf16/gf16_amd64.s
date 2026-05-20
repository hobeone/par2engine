#include "textflag.h"

// SET_CONV_MASK sets out = 0x00ff00ff:00ff00ff:00ff00ff:00ff00ff.
// This mask is used by STANDARD_TO_ALT_MAP to isolate the low byte of each 16-bit word.
// Clobbers tmp (GP register) and tmpx (XMM register).
#define SET_CONV_MASK(out, tmp, tmpx) \
	MOVQ   $0xff, tmp \
	MOVQ   tmp, out   \
	PXOR   tmpx, tmpx \
	PSHUFB tmpx, out  \
	PSRLW  $8, out

// SET_MUL_MASK sets out = 0x0f0f0f0f:0f0f0f0f:0f0f0f0f:0f0f0f0f.
// This mask is used to isolate the low 4 bits (one nibble) of each byte.
// Clobbers tmp (GP register) and tmpx (XMM register).
#define SET_MUL_MASK(out, tmp, tmpx) \
	MOVQ   $0xf, tmp  \
	MOVQ   tmp, out   \
	PXOR   tmpx, tmpx \
	PSHUFB tmpx, out

// STANDARD_TO_ALT_MAP converts 32 bytes of interleaved GF(2^16) elements (lo0,hi0,lo1,hi1,...)
// from two 16-byte XMM registers into a planar "alt map" format used by the PSHUFB lookups.
//
// The SSSE3 nibble lookups require all low bytes together and all high bytes together.
// PACKUSWB does the repacking: it packs 8 unsigned words from each source into 8 bytes.
//
// Input:
//   in0 = in[16:32] — second 16-byte chunk (elements 8..15) in standard LE interleaved format
//   in1 = in[ 0:16] — first  16-byte chunk (elements 0.. 7) in standard LE interleaved format
// Output after macro:
//   in0  = outHigh — all 16 high bytes: [hi8..hi15 | hi0..hi7]
//   outLow         — all 16 low  bytes: [lo8..lo15 | lo0..lo7]
// Clobbers in1 and tmp.
#define STANDARD_TO_ALT_MAP(in0, in1, convMask, outLow, tmp) \
	MOVO     in0, outLow      \
	PSRLW    $8, in0          \
	PAND     convMask, outLow \
	                          \
	MOVO     in1, tmp         \
	PSRLW    $8, in1          \
	PAND     convMask, tmp    \
	                          \
	PACKUSWB in1, in0         \
	PACKUSWB tmp, outLow

// ALT_TO_STANDARD_MAP is the inverse of STANDARD_TO_ALT_MAP.
// PUNPCKLBW interleaves the low 8 bytes of two registers; PUNPCKHBW does the high 8.
//
// Input:
//   inLow  = low  bytes plane: [lo8..lo15 | lo0..lo7]
//   inHigh = high bytes plane: [hi8..hi15 | hi0..hi7]
// Output after macro:
//   inLow = out0 — elements 8..15 in standard LE format: [lo8,hi8, lo9,hi9, ..., lo15,hi15]
//   out1  = out1 — elements 0.. 7 in standard LE format: [lo0,hi0, lo1,hi1, ...,  lo7, hi7]
#define ALT_TO_STANDARD_MAP(inLow, inHigh, out1) \
	MOVO      inLow, out1    \
	PUNPCKHBW inHigh, out1   \
	PUNPCKLBW inHigh, inLow

// MUL_ALT_MAP_BYTE computes one byte (low or high) of each element's product.
//
// For each byte b_i in the result:
//   b_i = s0[ inLow[i] & 0xf]         XOR
//         s4[(inLow[i] >> 4) & 0xf]   XOR
//         s8[ inHigh[i] & 0xf]        XOR
//         s12[(inHigh[i] >> 4) & 0xf]
//
// PSHUFB acts as a 16-way parallel table lookup: each byte of inLow selects an entry
// from the 16-byte table in the destination XMM register.
// mulMask = 0x0f0f... isolates the low nibble before each lookup.
#define MUL_ALT_MAP_BYTE(s0, s4, s8, s12, inLow, inHigh, mulMask, out, tmp0, tmp1) \
	MOVO   inLow, tmp0   \
	PAND   mulMask, tmp0 \
	MOVO   s0, out       \
	PSHUFB tmp0, out     \
	                     \
	MOVO   inLow, tmp0   \
	PSRLW  $4, tmp0      \
	PAND   mulMask, tmp0 \
	MOVO   s4, tmp1      \
	PSHUFB tmp0, tmp1    \
	PXOR   tmp1, out     \
	                     \
	MOVO   inHigh, tmp0  \
	PAND   mulMask, tmp0 \
	MOVO   s8, tmp1      \
	PSHUFB tmp0, tmp1    \
	PXOR   tmp1, out     \
	                     \
	MOVO   inHigh, tmp0  \
	PSRLW  $4, tmp0      \
	PAND   mulMask, tmp0 \
	MOVO   s12, tmp1     \
	PSHUFB tmp0, tmp1    \
	PXOR   tmp1, out

// MUL_ALT_MAP computes both the low and high result bytes using MUL_ALT_MAP_BYTE twice.
#define MUL_ALT_MAP(s0Low, s4Low, s8Low, s12Low, s0High, s4High, s8High, s12High, inLow, inHigh, mulMask, outLow, outHigh, tmp0, tmp1) \
	MUL_ALT_MAP_BYTE(s0Low,  s4Low,  s8Low,  s12Low,  inLow, inHigh, mulMask, outLow,  tmp0, tmp1) \
	MUL_ALT_MAP_BYTE(s0High, s4High, s8High, s12High, inLow, inHigh, mulMask, outHigh, tmp0, tmp1)

// MUL_STANDARD_MAP is the top-level macro: converts two 16-byte chunks from standard
// interleaved format, multiplies all 16 GF elements by the coefficient, then converts back.
//
// Register assignment after the macro completes:
//   in0 (was in[16:32]) = c * in[0:16]  (elements 0..7 multiplied)
//   in1 (was in[ 0:16]) = c * in[16:32] (elements 8..15 multiplied)
//
// tmp0..tmp3 are scratch registers clobbered during the operation.
#define MUL_STANDARD_MAP(s0Low, s4Low, s8Low, s12Low, s0High, s4High, s8High, s12High, in0, in1, convMask, mulMask, tmp0, tmp1, tmp2, tmp3) \
	STANDARD_TO_ALT_MAP(in0, in1, convMask, tmp0, tmp1)                                                                              \
	MUL_ALT_MAP(s0Low, s4Low, s8Low, s12Low, s0High, s4High, s8High, s12High, tmp0, in0, mulMask, in1, tmp1, tmp2, tmp3) \
	ALT_TO_STANDARD_MAP(in1, tmp1, in0)

// func mulSliceSSSE3(cEntry *mulTable64Entry, in, out []byte)
//
// Multiplies each GF(2^16) element in `in` by the coefficient described by `cEntry`,
// writing results to `out`. Processes exactly len(in)/32 chunks of 32 bytes (16 elements).
// The caller guarantees len(in) is a multiple of 32 and len(in) >= 32.
TEXT ·mulSliceSSSE3(SB), NOSPLIT, $0
	// Load the 8 sub-tables (each 16 bytes) from cEntry into X8-X15.
	// They stay resident for the entire loop — this is the key cache efficiency win:
	// 8 XMM registers × 16 bytes = 128 bytes, fitting entirely in L1 cache.
	MOVQ  cEntry+0(FP), AX
	MOVOU (AX), X8          // X8  = s0Low
	MOVOU 16(AX), X9        // X9  = s4Low
	MOVOU 32(AX), X10       // X10 = s8Low
	MOVOU 48(AX), X11       // X11 = s12Low
	MOVOU 64(AX), X12       // X12 = s0High
	MOVOU 80(AX), X13       // X13 = s4High
	MOVOU 96(AX), X14       // X14 = s8High
	MOVOU 112(AX), X15      // X15 = s12High

	SET_MUL_MASK(X7, AX, X2)   // X7 = 0x0f0f0f0f... (nibble mask)
	SET_CONV_MASK(X6, AX, X2)  // X6 = 0x00ff00ff... (lo-byte mask)

	MOVQ in_len+16(FP), AX  // AX = len(in) / 32 (number of 32-byte chunks)
	SHRQ $5, AX

	MOVQ in+8(FP), BX       // BX = &in[0]
	MOVQ out+32(FP), CX     // CX = &out[0]

loop:
	// Load 32 bytes: X1 = in[0:16] (first chunk), X0 = in[16:32] (second chunk).
	// Note the reversed order: MUL_STANDARD_MAP takes (in0=second, in1=first).
	MOVOU (BX), X1
	MOVOU 16(BX), X0

	MUL_STANDARD_MAP(X8, X9, X10, X11, X12, X13, X14, X15, X0, X1, X6, X7, X2, X3, X4, X5)

	// After MUL_STANDARD_MAP: X0 = c*in[0:16], X1 = c*in[16:32].
	MOVOU X0, (CX)
	MOVOU X1, 16(CX)

	ADDQ $32, BX
	ADDQ $32, CX
	SUBQ $1, AX
	JNZ  loop

	RET

// func mulAndAddSliceSSSE3(cEntry *mulTable64Entry, in, out []byte)
//
// Same as mulSliceSSSE3, but XORs the products into `out` rather than overwriting.
TEXT ·mulAndAddSliceSSSE3(SB), NOSPLIT, $0
	MOVQ  cEntry+0(FP), AX
	MOVOU (AX), X8
	MOVOU 16(AX), X9
	MOVOU 32(AX), X10
	MOVOU 48(AX), X11
	MOVOU 64(AX), X12
	MOVOU 80(AX), X13
	MOVOU 96(AX), X14
	MOVOU 112(AX), X15

	SET_MUL_MASK(X7, AX, X2)
	SET_CONV_MASK(X6, AX, X2)

	MOVQ in_len+16(FP), AX
	SHRQ $5, AX

	MOVQ in+8(FP), BX
	MOVQ out+32(FP), CX

loop:
	MOVOU (BX), X1
	MOVOU 16(BX), X0

	MUL_STANDARD_MAP(X8, X9, X10, X11, X12, X13, X14, X15, X0, X1, X6, X7, X2, X3, X4, X5)

	// XOR the products into the existing out values.
	MOVOU (CX), X2
	PXOR  X2, X0
	MOVOU X0, (CX)

	MOVOU 16(CX), X2
	PXOR  X2, X1
	MOVOU X1, 16(CX)

	ADDQ $32, BX
	ADDQ $32, CX
	SUBQ $1, AX
	JNZ  loop

	RET
