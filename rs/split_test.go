package rs

import (
	"fmt"
	"testing"

	"github.com/hobeone/par2engine/gf16"
)

// perGoroutineSplit decides how much of a chunk each goroutine multiplies, and
// the alignment it picks is what decides whether gf16's vector kernels consume a
// whole slice or leave a tail for the scalar path. These tests pin the
// alignment, not the arithmetic that produces it.

func TestPerGoroutineSplitIsVectorAligned(t *testing.T) {
	for _, dataLength := range []int{1, 16, 64, 100, 368, 7648, 11600, 15968, 38128, 1 << 20} {
		for _, goroutines := range []int{1, 2, 8, 32, 64} {
			t.Run(fmt.Sprintf("len=%d/g=%d", dataLength, goroutines), func(t *testing.T) {
				split := perGoroutineSplit(dataLength, goroutines)

				if split%gf16.KernelBlockBytes() != 0 {
					t.Errorf("perGoroutineSplit(%d, %d) = %d, want a multiple of %d -- "+
						"a split that is not lets every goroutine leave a scalar tail",
						dataLength, goroutines, split, gf16.KernelBlockBytes())
				}
				if split <= 0 {
					t.Fatalf("perGoroutineSplit(%d, %d) = %d, want a positive size", dataLength, goroutines, split)
				}

				// Every byte must land in exactly one goroutine's range.
				n := (dataLength + split - 1) / split
				if covered := n * split; covered < dataLength {
					t.Errorf("%d goroutines of %d bytes cover %d, short of %d", n, split, covered, dataLength)
				}
				if n > 1 && (n-1)*split >= dataLength {
					t.Errorf("%d goroutines of %d bytes leaves the last one empty for %d bytes", n, split, dataLength)
				}
			})
		}
	}
}

// TestPerGoroutineSplitUsesEveryGoroutine guards the other direction: rounding
// up costs parallelism, because a larger split means fewer ranges. A chunk big
// enough to give every goroutine a whole block must still do so.
func TestPerGoroutineSplitUsesEveryGoroutine(t *testing.T) {
	const goroutines = 32
	dataLength := goroutines * gf16.KernelBlockBytes() * 4

	split := perGoroutineSplit(dataLength, goroutines)
	if got := (dataLength + split - 1) / split; got != goroutines {
		t.Errorf("perGoroutineSplit(%d, %d) = %d yields %d ranges, want %d",
			dataLength, goroutines, split, got, goroutines)
	}
}

// TestPerGoroutineSplitBoundsTheRangesLost pins what rounding up actually costs,
// on lengths where it is not a no-op. The even split above cannot see it: 8192
// over 32 is already a whole block. The bound is that a rounded split stays
// under one block more than the exact share, so no chunk loses more than
// block/16 of the ranges the old 16-byte rounding produced.
func TestPerGoroutineSplitBoundsTheRangesLost(t *testing.T) {
	block := gf16.KernelBlockBytes()

	for _, tc := range []struct{ dataLength, goroutines int }{
		{11600, 32}, // the default memory limit's chunk, 32 cores
		{7648, 32},  // the chunk measured in issue #18
		{368, 32},
		{640, 64},
	} {
		t.Run(fmt.Sprintf("len=%d/g=%d", tc.dataLength, tc.goroutines), func(t *testing.T) {
			exact := max((tc.dataLength+tc.goroutines-1)/tc.goroutines, block)
			split := perGoroutineSplit(tc.dataLength, tc.goroutines)

			if split >= exact+block {
				t.Errorf("perGoroutineSplit(%d, %d) = %d, want less than %d "+
					"(the exact share %d plus one block)", tc.dataLength, tc.goroutines, split, exact+block, exact)
			}

			ranges := (tc.dataLength + split - 1) / split
			if ranges < 1 {
				t.Fatalf("split %d yields no ranges for %d bytes", split, tc.dataLength)
			}
		})
	}
}
